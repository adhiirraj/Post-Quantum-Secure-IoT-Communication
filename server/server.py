#!/usr/bin/env python3
"""
Post-Quantum Secure IoT Gateway Server
Terminates ML-KEM-512 key encapsulation and decrypts AES-256-GCM authenticated telemetry.
"""

import sys
import os
import socket
import struct
import zlib
import time
import json
import signal
from typing import Optional

from crypto_backend import PQCHostCrypto
from pcap import PcapWriter

# ANSI Color codes for rich logging
CLR_RESET   = "\033[0m"
CLR_BOLD    = "\033[1m"
CLR_RED     = "\033[91m"
CLR_GREEN   = "\033[92m"
CLR_YELLOW  = "\033[93m"
CLR_BLUE    = "\033[94m"
CLR_MAGENTA = "\033[95m"
CLR_CYAN    = "\033[96m"
CLR_WHITE   = "\033[97m"

SERVER_MAC  = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x01])
CLIENT_MAC  = bytes([0x10, 0xe2, 0xd5, 0x00, 0x00, 0x00])

SERVER_IP   = "192.168.1.100"
CLIENT_IP   = "192.168.1.50"

SERVER_PORT = 11111
CLIENT_PORT = 11110

BRIDGE_BIND_HOST = "127.0.0.1"
BRIDGE_BIND_PORT = 21111
SIM_DEST_PORT    = 21112

PQC_MAGIC   = 0x50514331
PQC_VERSION = 0x01

# Protocol Message Types
MSG_DISCOVERY_REQ  = 0x01
MSG_KEM_PUBLIC_KEY = 0x02
MSG_KEM_CIPHERTEXT = 0x03
MSG_SECURE_PAYLOAD = 0x04
MSG_ACK            = 0x05
MSG_ERROR          = 0xFF

STATUS_OK          = 0x00
STATUS_ERR_CRYPTO  = 0x04
STATUS_ERR_AUTH    = 0x05

PREAMBLE = b"\x55\x55\x55\x55\x55\x55\x55\xd5"


def ip_checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data)//2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_litex_frame(dest_mac: bytes, src_mac: bytes, ethertype: int, l3_payload: bytes) -> bytes:
    eth_data = dest_mac + src_mac + struct.pack("!H", ethertype) + l3_payload
    if len(eth_data) < 60:
        eth_data += b"\x00" * (60 - len(eth_data))
    return eth_data


def build_udp_ip_packet(src_ip_str: str, dst_ip_str: str, src_port: int, dst_port: int, udp_payload: bytes) -> bytes:
    src_ip = socket.inet_aton(src_ip_str)
    dst_ip = socket.inet_aton(dst_ip_str)

    udp_len = 8 + len(udp_payload)
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)

    ip_len = 20 + udp_len
    ip_hdr_no_csum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_len, 0, 0x4000, 64, 17, 0,
        src_ip, dst_ip
    )
    csum = ip_checksum(ip_hdr_no_csum)
    ip_hdr = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, ip_len, 0, 0x4000, 64, 17, csum,
        src_ip, dst_ip
    )
    return ip_hdr + udp_hdr + udp_payload


def build_pqc_msg(msg_type: int, seq_num: int, payload: bytes) -> bytes:
    hdr = struct.pack("<IBBHI", PQC_MAGIC, PQC_VERSION, msg_type, len(payload), seq_num)
    return hdr + payload


class PQCServer:
    def __init__(self, pcap_path: str = "pqc_session.pcap"):
        self.crypto = PQCHostCrypto()
        self.pcap = PcapWriter(pcap_path)
        self.server_key_ptr = None
        self.public_key_bytes: Optional[bytes] = None
        self.shared_secret: Optional[bytes] = None
        self.server_seq = 100
        self.received_packets = 0
        self.running = True

        # Socket binding
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((BRIDGE_BIND_HOST, BRIDGE_BIND_PORT))
        self.sock.settimeout(0.5)

    def log(self, tag: str, color: str, msg: str):
        timestamp = time.strftime("%H:%M:%S")
        print(f"{CLR_WHITE}[{timestamp}]{CLR_RESET} {color}{tag:<16}{CLR_RESET} {msg}", flush=True)

    def send_raw_frame(self, dest_mac: bytes, ethertype: int, l3_payload: bytes):
        raw_frame = build_litex_frame(dest_mac, SERVER_MAC, ethertype, l3_payload)
        # Write to PCAP (without preamble and trailing CRC for standard Wireshark analysis)
        pcap_frame = dest_mac + SERVER_MAC + struct.pack("!H", ethertype) + l3_payload
        self.pcap.write_packet(pcap_frame)
        self.sock.sendto(raw_frame, (BRIDGE_BIND_HOST, SIM_DEST_PORT))

    def send_udp_pqc_msg(self, msg_type: int, payload: bytes):
        self.server_seq += 1
        pqc_buf = build_pqc_msg(msg_type, self.server_seq, payload)
        ip_udp = build_udp_ip_packet(SERVER_IP, CLIENT_IP, SERVER_PORT, CLIENT_PORT, pqc_buf)
        self.send_raw_frame(CLIENT_MAC, 0x0800, ip_udp)

    def handle_arp(self, frame: bytes):
        if len(frame) < 42:
            return
        hwtype, proto, hwsize, protosize, opcode = struct.unpack("!HHBBH", frame[14:22])
        if opcode != 1:  # Not ARP request
            return

        sender_mac = frame[22:28]
        sender_ip = socket.inet_ntoa(frame[28:32])
        target_ip = socket.inet_ntoa(frame[38:42])

        if target_ip == SERVER_IP:
            self.log("[ARP REQUEST]", CLR_YELLOW, f"Who has {target_ip}? Tell {sender_ip} (MAC: {sender_mac.hex(':')})")
            # Build ARP Reply
            reply_arp = struct.pack(
                "!HHBBH6s4s6s4s18s",
                0x0001, 0x0800, 6, 4, 0x0002,  # Reply
                SERVER_MAC, socket.inet_aton(SERVER_IP),
                sender_mac, socket.inet_aton(sender_ip),
                b"\x00" * 18
            )
            self.send_raw_frame(sender_mac, 0x0806, reply_arp)
            self.log("[ARP REPLY]", CLR_GREEN, f"Replying {SERVER_IP} is at {SERVER_MAC.hex(':')}")

    def handle_pqc_packet(self, msg_type: int, payload: bytes, seq_num: int):
        self.received_packets += 1

        if msg_type == MSG_DISCOVERY_REQ:
            self.log("[DISCOVERY REQ]", CLR_CYAN, f"Received Discovery Request from IoT Node (seq={seq_num})")
            self.log("[ML-KEM-512]", CLR_MAGENTA, "Generating fresh ML-KEM-512 Keypair (NIST FIPS 203)...")
            
            # Clean up old key if any
            if self.server_key_ptr:
                self.crypto.free_kem_key(self.server_key_ptr)

            self.server_key_ptr, self.public_key_bytes = self.crypto.generate_kem_keypair()
            self.log("[ML-KEM-512]", CLR_MAGENTA, f"Generated Public Key ({len(self.public_key_bytes)} bytes)")
            self.log("[KEY EXCHANGE]", CLR_CYAN, f"Transmitting ML-KEM-512 Public Key to Node...")
            self.send_udp_pqc_msg(MSG_KEM_PUBLIC_KEY, self.public_key_bytes)

        elif msg_type == MSG_KEM_CIPHERTEXT:
            self.log("[KEM CIPHERTEXT]", CLR_YELLOW, f"Received Encapsulated Ciphertext ({len(payload)} bytes, seq={seq_num})")
            if not self.server_key_ptr:
                self.log("[ERROR]", CLR_RED, "No active private key for decapsulation!")
                return

            self.log("[ML-KEM-512]", CLR_MAGENTA, "Decapsulating shared secret with Private Key...")
            try:
                self.shared_secret = self.crypto.decapsulate_kem(self.server_key_ptr, payload)
                self.log("[SESSION KEY]", CLR_BOLD + CLR_GREEN, f"Derived 256-bit PQC Session Key: {self.shared_secret.hex()[:32]}...")
                self.log("[STATUS]", CLR_BOLD + CLR_GREEN, ">>> POST-QUANTUM SECURE CHANNEL ESTABLISHED <<<")

                # Acknowledge key exchange
                ack_payload = struct.pack("<BI", STATUS_OK, seq_num)
                self.send_udp_pqc_msg(MSG_ACK, ack_payload)
            except Exception as e:
                self.log("[ERROR]", CLR_RED, f"ML-KEM decapsulation failed: {e}")
                err_payload = struct.pack("<BI", STATUS_ERR_CRYPTO, seq_num)
                self.send_udp_pqc_msg(MSG_ACK, err_payload)

        elif msg_type == MSG_SECURE_PAYLOAD:
            self.log("[SECURE INGEST]", CLR_CYAN, f"Received Encrypted Telemetry Packet ({len(payload)} bytes, seq={seq_num})")
            if not self.shared_secret:
                self.log("[ERROR]", CLR_RED, "No active session key to decrypt payload!")
                return

            if len(payload) < 28:
                self.log("[ERROR]", CLR_RED, f"Payload too short for IV + Tag: {len(payload)} bytes")
                return

            iv = payload[:12]
            tag = payload[12:28]
            ciphertext = payload[28:]

            try:
                plaintext_bytes = self.crypto.decrypt_aes_gcm(self.shared_secret, iv, tag, ciphertext)
                plaintext_str = plaintext_bytes.decode("utf-8", errors="replace")

                self.log("[DECRYPTED]", CLR_BOLD + CLR_GREEN, f"AES-256-GCM Tag Verified! Plaintext ({len(plaintext_bytes)} B):")
                print(f"             {CLR_BOLD}{CLR_WHITE}{plaintext_str}{CLR_RESET}")

                try:
                    telemetry = json.loads(plaintext_str)
                    print(f"             {CLR_CYAN}-> Device: {telemetry.get('device')} | "
                          f"Seq: {telemetry.get('seq')} | "
                          f"Temp: {telemetry.get('temp')} C | "
                          f"Pressure: {telemetry.get('hPa')} hPa | "
                          f"Algo: {telemetry.get('pqc_kem')}{CLR_RESET}")
                except Exception:
                    pass

                # Send ACK
                ack_payload = struct.pack("<BI", STATUS_OK, seq_num)
                self.send_udp_pqc_msg(MSG_ACK, ack_payload)
            except Exception as e:
                self.log("[AUTH ERROR]", CLR_RED, f"AES-256-GCM Authentication Failed: {e}")
                err_payload = struct.pack("<BI", STATUS_ERR_AUTH, seq_num)
                self.send_udp_pqc_msg(MSG_ACK, err_payload)

        elif msg_type == MSG_ACK:
            if len(payload) >= 5:
                status, ack_seq = struct.unpack("<BI", payload[:5])
                self.log("[CLIENT ACK]", CLR_GREEN, f"Status={status}, AckSeq={ack_seq}")

        else:
            self.log("[UNKNOWN MSG]", CLR_YELLOW, f"Unhandled message type: 0x{msg_type:02x}")

    def run(self, max_packets: Optional[int] = None):
        print("=" * 65)
        print("   POST-QUANTUM CRYPTOGRAPHY IoT GATEWAY SERVER (HOST)   ")
        print(f"   Listening on {BRIDGE_BIND_HOST}:{BRIDGE_BIND_PORT} (Sim bridge -> {SIM_DEST_PORT})")
        print(f"   Gateway IP: {SERVER_IP}:{SERVER_PORT}  |  Node IP: {CLIENT_IP}:{CLIENT_PORT}")
        print("   Algorithms: ML-KEM-512 (Kyber) + AES-256-GCM AEAD       ")
        print("=" * 65 + "\n")

        processed_secure_msgs = 0

        while self.running:
            try:
                data, addr = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except KeyboardInterrupt:
                break

            self.log("[BRIDGE RX]", CLR_WHITE, f"Received {len(data)} raw bytes from {addr}")

            if len(data) < 14:
                continue

            # Strip preamble if present
            if data.startswith(PREAMBLE):
                frame = data[8:]
            else:
                frame = data

            # Strip CRC32 if present
            if len(frame) > 4:
                crc_recv = struct.unpack("<I", frame[-4:])[0]
                crc_calc = zlib.crc32(frame[:-4]) & 0xFFFFFFFF
                if crc_recv == crc_calc:
                    frame = frame[:-4]

            # Write received frame to PCAP
            self.pcap.write_packet(frame)

            if len(frame) < 14:
                continue

            dest_mac = frame[:6]
            src_mac  = frame[6:12]
            ethertype = struct.unpack("!H", frame[12:14])[0]

            if ethertype == 0x0806:  # ARP
                self.handle_arp(frame)

            elif ethertype == 0x0800:  # IPv4
                if len(frame) < 34:
                    continue
                version_ihl = frame[14]
                ihl = (version_ihl & 0x0F) * 4
                proto = frame[14 + 9]

                if proto == 17:  # UDP
                    udp_offset = 14 + ihl
                    if len(frame) < udp_offset + 8:
                        continue
                    src_port, dst_port, udp_len, _ = struct.unpack("!HHHH", frame[udp_offset:udp_offset + 8])
                    udp_payload = frame[udp_offset + 8:udp_offset + udp_len]

                    if len(udp_payload) >= 12:
                        magic, ver, mtype, plen, seq = struct.unpack("<IBBHI", udp_payload[:12])
                        if magic == PQC_MAGIC:
                            pqc_payload = udp_payload[12:12 + plen]
                            self.handle_pqc_packet(mtype, pqc_payload, seq)
                            if mtype == MSG_SECURE_PAYLOAD:
                                processed_secure_msgs += 1
                                if max_packets and processed_secure_msgs >= max_packets:
                                    self.log("[COMPLETE]", CLR_BOLD + CLR_GREEN, f"Reached target {max_packets} secure telemetry packets!")
                                    break

        self.cleanup()

    def cleanup(self):
        print(f"\n{CLR_YELLOW}[SERVER SHUTDOWN] Flushing PCAP and releasing cryptographic handles...{CLR_RESET}")
        if self.server_key_ptr:
            self.crypto.free_kem_key(self.server_key_ptr)
            self.server_key_ptr = None
        self.crypto.close()
        self.pcap.close()
        self.sock.close()
        print(f"{CLR_GREEN}[SERVER SHUTDOWN] Done. Recorded capture saved.{CLR_RESET}")


if __name__ == "__main__":
    max_pkts = None
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        max_pkts = int(sys.argv[1])

    server = PQCServer()

    def sig_handler(sig, frame):
        server.running = False

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    server.run(max_packets=max_pkts)
