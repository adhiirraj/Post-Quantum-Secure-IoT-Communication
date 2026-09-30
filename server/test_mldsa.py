#!/usr/bin/env python3
"""Quick test of ML-DSA-44 via libhost_pqc.so"""
import ctypes, os

lib_path = os.path.join(os.path.dirname(__file__), "..", "crypto", "libhost_pqc.so")
lib = ctypes.CDLL(lib_path)

PUBKEY_SIZE = 1312
PRIVKEY_SIZE = 2560
SIG_SIZE     = 2420

lib.mldsa44_keygen.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
lib.mldsa44_keygen.restype  = ctypes.c_int

lib.mldsa44_sign.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
    ctypes.c_char_p, ctypes.POINTER(ctypes.c_size_t)
]
lib.mldsa44_sign.restype = ctypes.c_int

lib.mldsa44_verify.argtypes = [
    ctypes.c_char_p, ctypes.c_char_p, ctypes.c_size_t,
    ctypes.c_char_p, ctypes.c_size_t
]
lib.mldsa44_verify.restype = ctypes.c_int

print("=== ML-DSA-44 Self-Test ===")

# Generate keypair
pubkey  = ctypes.create_string_buffer(PUBKEY_SIZE)
privkey = ctypes.create_string_buffer(PRIVKEY_SIZE)
ret = lib.mldsa44_keygen(pubkey, privkey)
assert ret == 0, f"Keygen failed: {ret}"
print(f"[+] ML-DSA-44 Keypair generated")
print(f"    Public key : {pubkey.raw[:16].hex()}...")
print(f"    Private key: {privkey.raw[:16].hex()}...")

# Sign a test message
msg = b"PQC IoT Handshake Authentication Token"
sig    = ctypes.create_string_buffer(SIG_SIZE)
sig_sz = ctypes.c_size_t(SIG_SIZE)
ret = lib.mldsa44_sign(privkey, msg, len(msg), sig, ctypes.byref(sig_sz))
assert ret == 0, f"Sign failed: {ret}"
print(f"[+] Signature generated: {sig_sz.value} bytes")
print(f"    Signature: {sig.raw[:16].hex()}...")

# Verify the signature
ret = lib.mldsa44_verify(pubkey, msg, len(msg), sig, sig_sz.value)
assert ret == 0, f"Verify failed: {ret}"
print(f"[+] Signature verified successfully!")

# Test with tampered message
bad_msg = b"PQC IoT Handshake Authentication TAMPERED"
ret_bad = lib.mldsa44_verify(pubkey, bad_msg, len(bad_msg), sig, sig_sz.value)
assert ret_bad != 0, "Should have rejected tampered message!"
print(f"[+] Tampered message correctly rejected (ret={ret_bad})")

print("\n=== ML-DSA-44 Self-Test PASSED ===")
