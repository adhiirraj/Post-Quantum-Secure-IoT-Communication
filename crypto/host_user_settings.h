#ifndef HOST_USER_SETTINGS_H
#define HOST_USER_SETTINGS_H

/* Math backend */
#define WOLFSSL_SP_MATH

/* Threading - single threaded on host for simplicity */
#define SINGLE_THREADED

/* No filesystem needed */
#define NO_FILESYSTEM

/* Small stack mode */
#define WOLFSSL_SMALL_STACK

/* ML-KEM (Kyber) - NIST FIPS 203 */
#define WOLFSSL_WC_MLKEM
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_HAVE_KYBER
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE256
#define WOLFSSL_SHAKE128
#define WOLFSSL_MLKEM_ENCAPSULATE_SMALL_MEM
#define WOLFSSL_MLKEM_MAKEKEY_SMALL_MEM

/* ML-DSA / Dilithium - NIST FIPS 204 */
#define HAVE_DILITHIUM
#define WOLFSSL_WC_DILITHIUM
#define WOLFSSL_DILITHIUM_SIGN_SMALL_MEM
#define WOLFSSL_DILITHIUM_VERIFY_SMALL_MEM

/* AES-GCM */
#define HAVE_AESGCM
#define WOLFSSL_SHA256
#define WOLFSSL_SHA512

/* HKDF */
#define HAVE_HKDF

/* Custom RNG from /dev/urandom on host */
extern int CustomRngGenerateBlock(unsigned char *, unsigned int);
#define CUSTOM_RAND_GENERATE_SEED CustomRngGenerateBlock

#endif /* HOST_USER_SETTINGS_H */
