# Protocol Specification: PQC IoT Wire Protocol (v1)

This document describes the binary wire format and exchange sequence for the Post-Quantum Cryptography IoT communication protocol (`PQC-v1`).

---

## 1. Protocol Overview

The protocol operates directly over UDP. It specifies an initial key establishment exchange based on NIST FIPS 203 ML-KEM-512, followed by authenticated, replay-resistant telemetry data streaming using AES-256-GCM.

- **Protocol Magic**: `0x50514331` (`"PQC1"` in ASCII, little-endian)
- **Protocol Version**: `0x01`
- **Default Server Port**: `11111`
- **Default Client Port**: `11110`

---

## 2. Packet Formats

Every protocol packet begins with a standard 12-byte packed header followed by an optional payload:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Magic (0x50514331)                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |   Msg Type    |          Payload Length       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                       Payload (variable)                      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Field Definitions:
- `magic` (32 bits, uint32_t): Fixed identifier `0x50514331`.
- `version` (8 bits, uint8_t): Current protocol version `0x01`.
- `msg_type` (8 bits, uint8_t): Type of message (see table below).
- `payload_len` (16 bits, uint16_t, little-endian): Length of the following payload in bytes.
- `seq_num` (32 bits, uint32_t, little-endian): Monotonically increasing sequence counter.

---

## 3. Message Types

| Type ID | Message Name | Direction | Payload Length | Description |
|:---:|:---|:---:|:---:|:---|
| `0x01` | `PQC_MSG_DISCOVERY_REQ` | Node -> Gateway | 0 bytes | Node requests gateway public key |
| `0x02` | `PQC_MSG_KEM_PUBLIC_KEY` | Gateway -> Node | 800 bytes | Gateway's ML-KEM-512 Public Key |
| `0x03` | `PQC_MSG_KEM_CIPHERTEXT` | Node -> Gateway | 768 bytes | Node's encapsulated ciphertext |
| `0x04` | `PQC_MSG_SECURE_PAYLOAD` | Node -> Gateway | 28+ bytes | AES-256-GCM encrypted telemetry |
| `0x05` | `PQC_MSG_ACK` | Gateway -> Node | 5 bytes | Acknowledgment message |
| `0xFF` | `PQC_MSG_ERROR` | Gateway -> Node | 5 bytes | Error status indication |

---

## 4. Message Details

### 4.1 Discovery Request (`0x01`)
- **Payload**: None (`payload_len = 0`).
- **Purpose**: Signals to the gateway that a constrained node is ready to initialize a quantum-secure session.

### 4.2 KEM Public Key (`0x02`)
- **Payload**: 800 bytes representing the uncompressed ML-KEM-512 public key polynomials.
- **Purpose**: Provides the public key for the node to encapsulate a secret.

### 4.3 KEM Ciphertext (`0x03`)
- **Payload**: 768 bytes representing the encapsulated ciphertext $C$.
- **Purpose**: Contains the encrypted seed from which both parties derive the 256-bit symmetric session key.

### 4.4 Secure Payload (`0x04`)
- **Payload Layout**:
  - `0..11` (12 bytes): Initialization Vector (random IV nonce).
  - `12..27` (16 bytes): AES-GCM Authentication Tag.
  - `28..N` (Variable): Ciphertext of the serialized JSON telemetry string.
- **Decryption Rule**:
  Gateway decrypts ciphertext using derived session key, IV, and validates the tag. If verification fails, packet is rejected.

### 4.5 Acknowledgment (`0x05`)
- **Payload Layout**:
  - `Byte 0` (uint8_t): Status code (`0x00 = STATUS_OK`, `0x04 = STATUS_ERR_CRYPTO`, `0x05 = STATUS_ERR_AUTH`).
  - `Bytes 1..4` (uint32_t, little-endian): Sequence number of the message being acknowledged.

---

## 5. Protocol Handshake Sequence

```
+--------------------+                                    +--------------------+
|  Bare-Metal Node   |                                    |   Gateway Server   |
| (192.168.1.50)     |                                    |  (192.168.1.100)   |
+--------------------+                                    +--------------------+
          |                                                         |
          | --- ARP Request (Who has 192.168.1.100?) -------------> |
          | <--- ARP Reply (192.168.1.100 is at 02:00:00:00:00:01) -|
          |                                                         |
          | --- PQC_MSG_DISCOVERY_REQ (seq=1) --------------------> |
          |                                                         | [Generates ML-KEM-512
          |                                                         |  Keypair]
          | <--- PQC_MSG_KEM_PUBLIC_KEY (800 bytes, seq=101) ------ |
          |                                                         |
[Encapsulates shared                                                |
 secret via ML-KEM-512;                                             |
 derives 256-bit session key]                                       |
          |                                                         |
          | --- PQC_MSG_KEM_CIPHERTEXT (768 bytes, seq=2) --------> |
          |                                                         | [Decapsulates ciphertext;
          |                                                         |  derives matching
          |                                                         |  256-bit session key]
          | <--- PQC_MSG_ACK (Status=OK, ack_seq=2) --------------- |
          |                                                         |
          |   === POST-QUANTUM SECURE SESSION ESTABLISHED ===       |
          |                                                         |
[Encrypts sensor JSON with                                          |
 AES-256-GCM + IV + Tag]                                            |
          |                                                         |
          | --- PQC_MSG_SECURE_PAYLOAD (seq=3) -------------------> |
          |                                                         | [Verifies Tag,
          |                                                         |  decrypts plaintext,
          |                                                         |  parses JSON telemetry]
          | <--- PQC_MSG_ACK (Status=OK, ack_seq=3) --------------- |
          |                                                         |
          | --- PQC_MSG_SECURE_PAYLOAD (seq=4) -------------------> |
          | <--- PQC_MSG_ACK (Status=OK, ack_seq=4) --------------- |
          v                                                         v
```
