WOLFSSL_ROOT ?= $(realpath ../client/wolfssl/..)
CC ?= gcc
PYTHON ?= python3

HOST_CFLAGS := -std=c99 -O2 -fPIC -Wall -Wextra -Wno-cpp \
	-include sys/types.h -include strings.h \
	-I./include -I../common -I$(WOLFSSL_ROOT) -I$(WOLFSSL_ROOT)/wolfssl \
	-DWOLFSSL_USER_SETTINGS -DWOLFSSL_CERT_GEN -DWOLFSSL_CERT_EXT -DWOLFSSL_DTLS_MTU \
	-DWC_ENABLE_ASYM_KEY_EXPORT
HOST_LDFLAGS := -shared
WOLFCRYPT_SRCS := $(wildcard $(WOLFSSL_ROOT)/wolfcrypt/src/*.c)
WOLFSSL_SRCS := $(wildcard $(WOLFSSL_ROOT)/src/*.c)
HOST_SRCS := $(WOLFCRYPT_SRCS) $(WOLFSSL_SRCS) \
	src/pqc_kem.c src/aes_gcm.c src/mldsa.c src/host_entropy.c src/dtls_host.c

.PHONY: all certs clean

all: libhost_pqc.so

libhost_pqc.so: $(HOST_SRCS) Makefile
	$(CC) $(HOST_CFLAGS) $(HOST_LDFLAGS) -o $@ $(HOST_SRCS)

mldsa_certgen: src/mldsa_certgen.c libhost_pqc.so
	$(CC) $(HOST_CFLAGS) -o $@ src/mldsa_certgen.c -L. -lhost_pqc -Wl,-rpath,'$$ORIGIN'

certs: mldsa_certgen
	./mldsa_certgen certs
	$(PYTHON) tools/embed_identity.py --cert-dir certs --output ../common/mldsa_identity.h

clean:
	rm -f libhost_pqc.so mldsa_certgen
