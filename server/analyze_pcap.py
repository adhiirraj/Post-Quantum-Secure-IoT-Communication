#!/usr/bin/env python3
"""
PCAP Packet Dissector for PQC IoT Communication Session
Parses and displays Ethernet, ARP, IPv4, UDP, and custom PQC Protocol headers.
"""

import sys
import os
import struct

PQC_MAGIC = 0x50514331

MSG_TYPES = {
    0x01: "DISCOVERY_REQ",
    0x02: "KEM_PUBLIC_KEY (ML-KEM-512)",
    0x03: "KEM_CIPHERTEXT (ML-KEM-512)",
    0x04: "SECURE_PAYLOAD (AES-256-GCM)",
    0x05: "ACK",
    0xFF: "ERROR"
}

def analyze_pcap(path: str):
    if not os.path.exists(path):
        print(f"Error: file not found: {path}")
        return

    with open(path, "rb") as f:
        ghdr = f.read(24)
        if len(ghdr) < 24:
            print("Invalid PCAP file header.")
            return

        magic, v_maj, v_min, tz, sig, snaplen, linktype = struct.unpack("<IHHiIII", ghdr)
        print("=" * 78)
        print(f"  PCAP CAPTURE FILE ANALYSIS: {os.path.basename(path)}")
        print(f"  Format: PCAP v{v_maj}.{v_min} | LinkType: {linktype} (Ethernet) | SnapLen: {snaplen}")
        print("=" * 78)

        pkt_idx = 0
        while True:
            phdr = f.read(16)
            if len(phdr) < 16:
                break
            pkt_idx += 1
            ts_sec, ts_usec, incl_len, orig_len = struct.unpack("<IIII", phdr)
            raw = f.read(incl_len)

            print(f"\n[Packet #{pkt_idx:02d}] {ts_sec}.{ts_usec:06d} | Wire Size: {incl_len} bytes")
            if len(raw) < 14:
                print(f"  Raw: {raw.hex()}")
                continue

            dst_mac = ":".join(f"{b:02x}" for b in raw[:6])
            src_mac = ":".join(f"{b:02x}" for b in raw[6:12])
            ethertype = struct.unpack("!H", raw[12:14])[0]

            print(f"  Ethernet: Src={src_mac} -> Dst={dst_mac} | Type=0x{ethertype:04x}", end="")

            if ethertype == 0x0806:  # ARP
                print(" (ARP)")
                if len(raw) >= 42:
                    hw, proto, hlen, plen, op = struct.unpack("!HHBBH", raw[14:22])
                    s_mac = ":".join(f"{b:02x}" for b in raw[22:28])
                    s_ip  = ".".join(str(b) for b in raw[28:32])
                    t_mac = ":".join(f"{b:02x}" for b in raw[32:38])
                    t_ip  = ".".join(str(b) for b in raw[38:42])
                    op_name = "Request" if op == 1 else ("Reply" if op == 2 else f"Op={op}")
                    print(f"    ARP {op_name}: Sender={s_ip} ({s_mac}) -> Target={t_ip}")

            elif ethertype == 0x0800:  # IPv4
                print(" (IPv4)")
                if len(raw) < 34:
                    continue
                ver_ihl = raw[14]
                ihl = (ver_ihl & 0x0F) * 4
                proto = raw[14 + 9]
                src_ip = ".".join(str(b) for b in raw[14 + 12:14 + 16])
                dst_ip = ".".join(str(b) for b in raw[14 + 16:14 + 20])
                print(f"    IPv4: {src_ip} -> {dst_ip} (Protocol={proto})")

                if proto == 17:  # UDP
                    udp_off = 14 + ihl
                    if len(raw) >= udp_off + 8:
                        sport, dport, ulen, _ = struct.unpack("!HHHH", raw[udp_off:udp_off + 8])
                        print(f"    UDP: Port {sport} -> {dport} (Length={ulen} bytes)")

                        udp_payload = raw[udp_off + 8:udp_off + ulen]
                        if len(udp_payload) >= 12:
                            pqc_magic, ver, mtype, plen, seq = struct.unpack("<IBBHI", udp_payload[:12])
                            if pqc_magic == PQC_MAGIC:
                                type_name = MSG_TYPES.get(mtype, f"UNKNOWN(0x{mtype:02x})")
                                print(f"    >>> PQC Protocol: Type={type_name} | Seq={seq} | PayloadLen={plen} bytes")
                                data_chunk = udp_payload[12:12 + plen]
                                if mtype == 0x01:
                                    print("        [Discovery Request from IoT Node]")
                                elif mtype == 0x02:
                                    print(f"        [Gateway ML-KEM-512 Public Key: {len(data_chunk)} bytes]")
                                    print(f"        Key Fingerprint: {data_chunk[:16].hex()}...{data_chunk[-16:].hex()}")
                                elif mtype == 0x03:
                                    print(f"        [Client Encapsulated Ciphertext: {len(data_chunk)} bytes]")
                                    print(f"        Ciphertext: {data_chunk[:16].hex()}...{data_chunk[-16:].hex()}")
                                elif mtype == 0x04:
                                    iv = data_chunk[:12]
                                    tag = data_chunk[12:28]
                                    ct = data_chunk[28:]
                                    print(f"        [Encrypted AEAD Telemetry: IV={iv.hex()} | Tag={tag.hex()}]")
                                    print(f"        Ciphertext ({len(ct)} bytes): {ct.hex()}")
                                elif mtype == 0x05:
                                    status, ack_seq = struct.unpack("<BI", data_chunk[:5])
                                    print(f"        [ACK: Status={status} (OK) | AckSeq={ack_seq}]")

        print("\n" + "=" * 78)
        print(f"  Total Packets Analyzed: {pkt_idx}")
        print("=" * 78)

if __name__ == "__main__":
    pcap_file = sys.argv[1] if len(sys.argv) > 1 else "/home/asus/pqc/Post-Quantum-Secure-IoT-Communication/pqc_session.pcap"
    analyze_pcap(pcap_file)
