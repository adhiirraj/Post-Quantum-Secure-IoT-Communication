# Architecture Specification: Post-Quantum Secure IoT Communication

This document specifies the system architecture for the Post-Quantum Cryptography (PQC) secure communication stack designed for resource-constrained RISC-V IoT nodes communicating with a host gateway server.

---

## 1. High-Level Architecture

The system provides quantum-resilient confidentiality and authenticity between an edge device (constrained RISC-V SoC) and an IoT gateway:

```
+----------------------------------------------------+          +--------------------------------------------+
|             LiteX Bare-Metal IoT Node              |          |             Host Gateway Server            |
|                                                    |          |                                            |
|  +----------------------------------------------+  |          |  +--------------------------------------+  |
|  |             Sensors / Application            |  |          |  |       Telemetry Ingest & Analytics   |  |
|  +----------------------------------------------+  |          |  +--------------------------------------+  |
|                        |                           |          |                     ^                      |
|  +----------------------------------------------+  |          |  +--------------------------------------+  |
|  |        PQC State Machine (client_pqc.c)      |  |          |  |         PQCServer (server.py)        |  |
|  +----------------------------------------------+  |          |  +--------------------------------------+  |
|           |                            |           |          |            |                    |          |
|  +-----------------+          +-----------------+  |          |  +-----------------+  +-----------------+  |
|  |   wolfCrypt PQC |          |   wolfCrypt AES |  |          |  |  libhost_pqc.so |  |   PCAP Logger   |  |
|  |   (ML-KEM-512)  |          |   (256-bit GCM) |  |          |  |  (C FFI Wrapper)|  |  (pcap.py)      |  |
|  +-----------------+          +-----------------+  |          |  +-----------------+  +-----------------+  |
|           \                            /           |          |            \                    /          |
|  +----------------------------------------------+  |          |  +--------------------------------------+  |
|  |        LiteX Network Driver (net_client.c)   |  |          |  |       Python UDP Network Bridge      |  |
|  +----------------------------------------------+  |          |  +--------------------------------------+  |
|                        |                           |          |                     ^                      |
|  +----------------------------------------------+  |          |                     |                      |
|  |          LiteEth MAC Peripheral Driver       |  |          |                     |                      |
|  +----------------------------------------------+  |          |                     |                      |
+------------------------|---------------------------+          +---------------------|----------------------+
                         |                                                            |
                         |               Simulated Ethernet Bridge (UDP)              |
                         +------------------------------------------------------------+
                               Node (127.0.0.1:21112) <---> Host (127.0.0.1:21111)
```

---

## 2. Hardware Platform & Simulation Environment

### 2.1 SoC Specifications (LiteX / VexRiscv)
- **CPU**: VexRiscv (RV32IM architecture, 32-bit integer and multiply/divide extension).
- **Clock**: 1.0 MHz nominal simulation clock.
- **Memory Map**:
  - `0x00000000 - 0x0001ffff`: 128 KiB Boot ROM (LiteX BIOS)
  - `0x10000000 - 0x10001fff`: 8 KiB Fast On-Chip Scratchpad SRAM
  - `0x40000000 - 0x46400000`: 100 MiB Main RAM (DDR/SRAM backing firmware execution)
  - `0xf0000000 - 0xf0003fff`: Memory-Mapped CSR Register Space
- **Peripherals**:
  - **UART**: Memory-mapped register at `0xf0002800` (bridged via `serial2console.so` with non-blocking EOF protection).
  - **Timer**: 32-bit hardware down-counter.
  - **LiteEth MAC**: Memory-mapped buffer descriptor SRAM at `0xf0000800` (configured with `ETHMAC_SLOT_SIZE=2048` bytes).

### 2.2 Verilator Simulation Bridge
The hardware simulation is compiled using Verilator (`Vsim`). The simulated Ethernet PHY maps direct stream FIFOs (`eth0_source_*` and `eth0_sink_*`) into a custom dynamic C shared module (`modules/ethernet.so`).

- **Non-Privileged Bridge**: Operates entirely in user-space without requiring root capabilities, TAP virtual network adapters, or TUN devices.
- **Virtual Socket Pair**:
  - Node Transmission: `127.0.0.1:21112` -> `127.0.0.1:21111`
  - Host Reception & Injection: `127.0.0.1:21111` -> `127.0.0.1:21112`
- **Frame Format**: Full Ethernet II Layer 2 frames (MAC destination, MAC source, 2-byte EtherType, payload).

---

## 3. Cryptographic Stack

### 3.1 Post-Quantum Key Encapsulation (ML-KEM-512)
- **Standard**: NIST FIPS 203 (Module-Lattice-Based Key-Encapsulation Mechanism).
- **Security Strength**: NIST Category 1 (~128 bits post-quantum security margin).
- **Parameters**:
  - Public Key: $k=2$, matrix polynomials $A \in R_q^{2 \times 2}$, dimension 800 bytes.
  - Ciphertext: $u \in R_q^2, v \in R_q$, dimension 768 bytes.
  - Shared Secret: Derived 256-bit symmetric entropy block (32 bytes).
- **Target Implementation**: wolfSSL / wolfCrypt with `-DWOLFSSL_WC_MLKEM` compiled for 32-bit RISC-V bare-metal.

### 3.2 Authenticated Encryption (AES-256-GCM AEAD)
- **Standard**: NIST SP 800-38D.
- **Key**: 256-bit symmetric key derived directly from ML-KEM-512 decapsulation.
- **Initialization Vector (IV)**: 96-bit (12 bytes) fresh cryptographically random nonce generated per message.
- **Authentication Tag**: 128-bit (16 bytes) GMAC tag ensuring authenticity and integrity of the sensor telemetry.
- **Plaintext Format**: Structured UTF-8 JSON environmental telemetry.

---

## 4. Software Subsystems

### 4.1 Client Firmware (`/client`)
- `src/main.c`: Bare-metal hardware initialization, UART setup, network initialization, and main telemetry generation loop.
- `src/client_pqc.c`: State machine managing node discovery, ML-KEM public key processing, encapsulation, and payload encryption.
- `src/net_client.c`: LiteEth UDP/IP stack abstraction layer implementing ARP caching, UDP transmission, and frame reception dispatch.

### 4.2 Gateway Server (`/server`)
- `server.py`: Host gateway service handling ARP resolution, generating ephemeral ML-KEM keypairs, decapsulating shared secrets, verifying AES-GCM tags, and printing authenticated telemetry.
- `crypto_backend.py`: Python `ctypes` wrapper interfacing with `libhost_pqc.so` (native wolfCrypt x86_64 build).
- `pcap.py`: Pure-Python libpcap file writer saving bit-exact packet captures for Wireshark inspection.
- `analyze_pcap.py`: Dissector tool inspecting captured PCAP traces and verifying layer-by-layer compliance.

### 4.3 Cryptographic Libraries (`/crypto`)
- `src/pqc_kem.c`: Clean C wrapper for `wc_MlKemKey_MakeKey`, `wc_MlKemKey_Encapsulate`, and `wc_MlKemKey_Decapsulate`.
- `src/aes_gcm.c`: Wrapper for `wc_AesGcmEncrypt` and `wc_AesGcmDecrypt` handling tag calculation and verification.
