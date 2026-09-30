"""
Post-Quantum Cryptography (PQC) Host Backend
Interfaces with libhost_pqc.so for ML-KEM-512 and AES-256-GCM operations.
"""

import ctypes
import os
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class WC_RNG(ctypes.Structure):
    _fields_ = [("dummy", ctypes.c_byte * 1024)]


class PQCHostCrypto:
    def __init__(self, lib_path: Optional[str] = None):
        if lib_path is None:
            base_dir = os.path.dirname(os.path.abspath(__file__))
            lib_path = os.path.join(base_dir, "..", "crypto", "libhost_pqc.so")

        self.lib = ctypes.CDLL(lib_path)

        # Setup ctypes signatures
        self.lib.pqc_kem_rng_init.argtypes = [ctypes.c_void_p]
        self.lib.pqc_kem_rng_init.restype = ctypes.c_int

        self.lib.pqc_kem_rng_free.argtypes = [ctypes.c_void_p]
        self.lib.pqc_kem_rng_free.restype = None

        self.lib.pqc_kem_generate_keypair.argtypes = [
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
        ]
        self.lib.pqc_kem_generate_keypair.restype = ctypes.c_int

        self.lib.pqc_kem_decapsulate.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
        ]
        self.lib.pqc_kem_decapsulate.restype = ctypes.c_int

        self.lib.pqc_kem_free_key.argtypes = [ctypes.c_void_p]
        self.lib.pqc_kem_free_key.restype = None

        # Initialize RNG
        self._rng = WC_RNG()
        ret = self.lib.pqc_kem_rng_init(ctypes.byref(self._rng))
        if ret != 0:
            raise RuntimeError(f"Failed to initialize wolfSSL RNG: {ret}")

    def generate_kem_keypair(self) -> Tuple[ctypes.c_void_p, bytes]:
        """
        Generates ML-KEM-512 Keypair.
        Returns:
            (key_ptr, public_key_bytes)
        """
        key_ptr = ctypes.c_void_p()
        pub_buf = ctypes.create_string_buffer(800)

        ret = self.lib.pqc_kem_generate_keypair(
            ctypes.byref(key_ptr), pub_buf, 800, ctypes.byref(self._rng)
        )
        if ret != 0:
            raise RuntimeError(f"ML-KEM key generation failed: {ret}")

        return key_ptr, pub_buf.raw

    def decapsulate_kem(self, key_ptr: ctypes.c_void_p, ciphertext: bytes) -> bytes:
        """
        Decapsulates ML-KEM-512 ciphertext using private key.
        Returns:
            32-byte shared secret
        """
        if len(ciphertext) != 768:
            raise ValueError(f"Invalid ML-KEM-512 ciphertext length: {len(ciphertext)} (expected 768)")

        ss_buf = ctypes.create_string_buffer(32)
        ct_buf = ctypes.create_string_buffer(ciphertext, 768)

        ret = self.lib.pqc_kem_decapsulate(key_ptr, ct_buf, 768, ss_buf, 32)
        if ret != 0:
            raise RuntimeError(f"ML-KEM decapsulation failed: {ret}")

        return ss_buf.raw

    def free_kem_key(self, key_ptr: ctypes.c_void_p):
        if key_ptr:
            self.lib.pqc_kem_free_key(key_ptr)

    def decrypt_aes_gcm(self, key: bytes, iv: bytes, tag: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        """
        Decrypts AES-256-GCM payload and verifies authentication tag.
        """
        if len(key) != 32:
            raise ValueError(f"Invalid AES-256 key size: {len(key)}")
        if len(iv) != 12:
            raise ValueError(f"Invalid GCM IV size: {len(iv)}")
        if len(tag) != 16:
            raise ValueError(f"Invalid GCM tag size: {len(tag)}")

        # cryptography AESGCM takes ciphertext + tag
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(iv, ciphertext + tag, aad if aad else None)

    def encrypt_aes_gcm(self, key: bytes, iv: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
        """
        Encrypts plaintext with AES-256-GCM.
        Returns:
            (ciphertext, 16_byte_tag)
        """
        aesgcm = AESGCM(key)
        ct_tag = aesgcm.encrypt(iv, plaintext, aad if aad else None)
        ciphertext = ct_tag[:-16]
        tag = ct_tag[-16:]
        return ciphertext, tag

    def close(self):
        try:
            self.lib.pqc_kem_rng_free(ctypes.byref(self._rng))
        except Exception:
            pass
