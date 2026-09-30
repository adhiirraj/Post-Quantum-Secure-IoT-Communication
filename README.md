# Post-Quantum Secure IoT Communication

A complete, working bare-metal Post-Quantum Cryptography (PQC) secure communication stack for RISC-V IoT nodes. Features **ML-KEM-512** (Kyber, NIST FIPS 203) key encapsulation and authenticated **AES-256-GCM** payload encryption running on an emulated LiteX + Verilator RISC-V SoC communicating with a Python-based IoT Gateway Server.

---

## Key Highlights

- **Post-Quantum Key Exchange**: Implements NIST FIPS 203 **ML-KEM-512** via wolfSSL / wolfCrypt. Derives a fresh 256-bit symmetric session key with quantum resistance (~128-bit post-quantum security).
- **Authenticated Telemetry Ingestion**: Employs **AES-256-GCM AEAD** with per-packet 96-bit random IVs and 128-bit authentication tags to protect IoT sensor data against eavesdropping, tampering, and replay.
- **Bare-Metal RISC-V Target**: Executes directly on a simulated 32-bit RISC-V CPU (`VexRiscv` at 1MHz) running bare-metal C firmware with custom LiteEth Ethernet peripherals.
- **Rootless Virtual Ethernet Bridge**: Transparent, non-privileged simulated network bridge operating via local UDP sockets (`127.0.0.1:21112 <-> 21111`) without requiring root access, TAP devices, or kernel network manipulation.
- **Bit-Exact PCAP Logging**: Automatically records every Ethernet, ARP, IPv4, UDP, and PQC protocol frame directly into standard `pqc_session.pcap` format compatible with Wireshark and our built-in CLI dissector.

---

## Architecture Overview

```
 +---------------------------------------------+        +----------------------------------------+
 |         LiteX Bare-Metal IoT Node           |        |          PQC Gateway Server            |
 |                                             |        |                                        |
 |  [Sensors] Environmental Telemetry JSON     |        |  [Analytics] Telemetry Dashboard       |
 |      |                                      |        |      ^                                 |
 |  [wolfCrypt] AES-256-GCM AEAD Encrypt       |        |  [wolfCrypt] AES-256-GCM AEAD Decrypt  |
 |      |                                      |        |      ^                                 |
 |  [wolfCrypt] ML-KEM-512 Encapsulate         | <====> |  [wolfCrypt] ML-KEM-512 Keygen/Decap   |
 |      |                                      |        |      |                                 |
 |  [LiteEth] Bare-Metal UDP/IP MAC Driver     |        |  [Bridge] Python UDP Gateway Server    |
 +---------------------------------------------+        +----------------------------------------+
                        \                                      /
                         +---- Virtual Localhost Bridge ------+
                               (127.0.0.1:21112 <-> 21111)
```

For detailed diagrams and architectural specifications, see [`docs/ARCHITECTURE.md`](file:///home/asus/pqc/Post-Quantum-Secure-IoT-Communication/docs/ARCHITECTURE.md) and [`docs/PROTOCOL.md`](file:///home/asus/pqc/Post-Quantum-Secure-IoT-Communication/docs/PROTOCOL.md).

---

## Directory Structure

```text
Post-Quantum-Secure-IoT-Communication/
├── client/                      # Bare-metal RISC-V firmware
│   ├── include/                 # Client headers (net_client.h, client_pqc.h)
│   ├── src/                     # Client logic (main.c, net_client.c, client_pqc.c)
│   ├── Makefile                 # RISC-V cross-compilation Makefile
│   ├── linker.ld                # Memory layout linker script (0x40000000)
│   ├── boot.elf                 # Linked RISC-V ELF binary
│   └── boot.bin                 # Flat binary image for LiteX Main RAM
├── common/                      # Shared protocol definitions
│   └── protocol.h               # Binary wire protocol headers and constants
├── crypto/                      # Cryptographic abstraction wrappers
│   ├── include/                 # PQC KEM and AES-GCM headers
│   ├── src/                     # C implementations wrapping wolfCrypt
│   ├── Makefile                 # Builds x86_64 host shared library (libhost_pqc.so)
│   └── libhost_pqc.so           # Host native crypto dynamic library
├── docs/                        # Specifications and design documentation
│   ├── ARCHITECTURE.md          # Hardware SoC & software subsystem specs
│   └── PROTOCOL.md              # Wire format, packet layout, and sequence charts
├── server/                      # Host Gateway Server
│   ├── server.py                # Main PQC gateway server & telemetry receiver
│   ├── crypto_backend.py        # Python ctypes interface for wolfCrypt
│   ├── pcap.py                  # Standard libpcap packet capture writer
│   └── analyze_pcap.py          # CLI PCAP packet dissector and inspector
├── pqc_session.pcap             # Captured session traces (Wireshark-ready)
└── run_demo.sh                  # One-click automated demonstration script
```

---

## Quick Start (Automated Demo)

To run the complete automated end-to-end demonstration (Gateway Server + LiteX RISC-V simulation + Live Decryption + PCAP Analysis):

```bash
cd /home/asus/pqc/Post-Quantum-Secure-IoT-Communication
./run_demo.sh 3
```

This single script:
1. Spawns the PQC Gateway Server in the background.
2. Boots the LiteX / Verilator RISC-V simulation.
3. Automatically completes the ARP handshake, ML-KEM-512 key encapsulation, and session key agreement.
4. Streams 3 authenticated telemetry packets encrypted with AES-256-GCM.
5. Verifies and decrypts all payloads in real-time.
6. Flushes `pqc_session.pcap` and executes the packet dissector.

---

## Running Manually

### 1. Build Client Firmware (if modifying C code)
```bash
cd /home/asus/pqc/Post-Quantum-Secure-IoT-Communication/client
make clean && make

# Update simulation RAM init file
python3 -c "
with open('boot.bin', 'rb') as f: data = f.read()
if len(data) % 4 != 0: data += b'\x00' * (4 - len(data) % 4)
with open('/home/asus/pqc/Constraint_Env_Sim/build/sim/gateware/sim_main_ram.init', 'w') as f:
    for i in range(0, len(data), 4):
        f.write(f'{int.from_bytes(data[i:i+4], \"little\"):08x}\n')
"
```

### 2. Start Gateway Server
```bash
cd /home/asus/pqc/Post-Quantum-Secure-IoT-Communication/server
python3 -u server.py 5
```

### 3. Launch LiteX RISC-V Emulation
In a second terminal:
```bash
cd /home/asus/pqc/Constraint_Env_Sim/build/sim/gateware
./run_sim.sh < /dev/null
```

---

## Verifying Packet Captures

All network interactions are saved in bit-exact standard libpcap format to `pqc_session.pcap`.

Inspect the capture file with the included dissector:
```bash
python3 /home/asus/pqc/Post-Quantum-Secure-IoT-Communication/server/analyze_pcap.py pqc_session.pcap
```

Sample output:
```text
==============================================================================
  PCAP CAPTURE FILE ANALYSIS: pqc_session.pcap
  Format: PCAP v2.4 | LinkType: 1 (Ethernet) | SnapLen: 65535
==============================================================================

[Packet #01] 1790765620.084057 | Wire Size: 60 bytes
  Ethernet: Src=10:e2:d5:00:00:00 -> Dst=ff:ff:ff:ff:ff:ff | Type=0x0806 (ARP)
    ARP Request: Sender=192.168.1.50 (10:e2:d5:00:00:00) -> Target=192.168.1.100

[Packet #02] 1790765620.084315 | Wire Size: 60 bytes
  Ethernet: Src=02:00:00:00:00:01 -> Dst=10:e2:d5:00:00:00 | Type=0x0806 (ARP)
    ARP Reply: Sender=192.168.1.100 (02:00:00:00:00:01) -> Target=192.168.1.50

[Packet #03] 1790765620.101056 | Wire Size: 60 bytes
  Ethernet: Src=10:e2:d5:00:00:00 -> Dst=02:00:00:00:00:01 | Type=0x0800 (IPv4)
    UDP: Port 11110 -> 11111 (Length=20 bytes)
    >>> PQC Protocol: Type=DISCOVERY_REQ | Seq=1 | PayloadLen=0 bytes

[Packet #04] 1790765620.101590 | Wire Size: 854 bytes
  Ethernet: Src=02:00:00:00:00:01 -> Dst=10:e2:d5:00:00:00 | Type=0x0800 (IPv4)
    UDP: Port 11111 -> 11110 (Length=820 bytes)
    >>> PQC Protocol: Type=KEM_PUBLIC_KEY (ML-KEM-512) | Seq=101 | PayloadLen=800 bytes
        [Gateway ML-KEM-512 Public Key: 800 bytes]

[Packet #05] 1790765621.135012 | Wire Size: 824 bytes
  Ethernet: Src=10:e2:d5:00:00:00 -> Dst=02:00:00:00:00:01 | Type=0x0800 (IPv4)
    UDP: Port 11110 -> 11111 (Length=788 bytes)
    >>> PQC Protocol: Type=KEM_CIPHERTEXT (ML-KEM-512) | Seq=2 | PayloadLen=768 bytes
        [Client Encapsulated Ciphertext: 768 bytes]

[Packet #06] 1790765621.135430 | Wire Size: 59 bytes
  Ethernet: Src=02:00:00:00:00:01 -> Dst=10:e2:d5:00:00:00 | Type=0x0800 (IPv4)
    >>> PQC Protocol: Type=ACK | Seq=102 | PayloadLen=5 bytes

[Packet #07] 1790765624.737214 | Wire Size: 164 bytes
  Ethernet: Src=10:e2:d5:00:00:00 -> Dst=02:00:00:00:00:01 | Type=0x0800 (IPv4)
    >>> PQC Protocol: Type=SECURE_PAYLOAD (AES-256-GCM) | Seq=3 | PayloadLen=108 bytes
        [Encrypted AEAD Telemetry: IV=65af05463b62577c172a48b4 | Tag=ecd8f9c5f60de9419da220d235ce5f40]
```
