"""
Lightweight PCAP Capture Writer
Writes standard libpcap format files (.pcap) without external dependencies.
"""

import struct
import time


class PcapWriter:
    def __init__(self, filename: str):
        self.filename = filename
        self.file = open(filename, "wb")
        # Global Header:
        # magic_number (4B) = 0xa1b2c3d4 (little endian)
        # version_major (2B) = 2
        # version_minor (2B) = 4
        # thiszone (4B) = 0 (GMT)
        # sigfigs (4B) = 0
        # snaplen (4B) = 65535
        # network (4B) = 1 (LINKTYPE_ETHERNET)
        hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        self.file.write(hdr)
        self.file.flush()

    def write_packet(self, packet_bytes: bytes, timestamp: float = None):
        if timestamp is None:
            timestamp = time.time()
        ts_sec = int(timestamp)
        ts_usec = int((timestamp - ts_sec) * 1_000_000)

        length = len(packet_bytes)
        # Packet Record Header:
        # ts_sec (4B), ts_usec (4B), incl_len (4B), orig_len (4B)
        pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, length, length)
        self.file.write(pkt_hdr + packet_bytes)
        self.file.flush()

    def close(self):
        if self.file and not self.file.closed:
            self.file.flush()
            self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
