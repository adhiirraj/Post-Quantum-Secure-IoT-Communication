BUILD_DIR ?= /home/asus/pqc/Constraint_Env_Sim/build/sim

include $(BUILD_DIR)/software/include/generated/variables.mak
include $(SOC_DIRECTORY)/software/common.mak

WOLFSSL_ROOT ?= $(realpath wolfssl/..)

SRCS += $(wildcard wolfcrypt/src/*.c)
SRCS += $(wildcard wolfssl_src/*.c)
SRCS += $(wildcard src/*.c)
SRCS += ../crypto/src/pqc_kem.c ../crypto/src/aes_gcm.c ../crypto/src/mldsa.c

OBJECTS  = crt0.o
OBJECTS += $(SRCS:.c=.o)

INC  = -I./include -I../common -I../crypto/include -I. -I$(WOLFSSL_ROOT) -I./wolfssl -I./wolfssl/wolfcrypt

CFLAGS += $(INC) -DWOLFSSL_USER_SETTINGS

vpath %.a $(PACKAGES:%=$(BUILD_DIR)/software/%)

all: boot.bin

%.bin: %.elf
	$(OBJCOPY) -O binary $< $@
ifneq ($(OS),Windows_NT)
	chmod -x $@
endif

boot.elf: $(OBJECTS)
	$(CC) $(LDFLAGS) -T linker.ld -N -o $@ \
		$(OBJECTS) \
		$(PACKAGES:%=-L$(BUILD_DIR)/software/%) \
		-Wl,--whole-archive \
		-Wl,--gc-sections \
		-Wl,-Map,$@.map \
		$(LIBS:lib%=-l%)

ifneq ($(OS),Windows_NT)
	chmod -x $@
endif

-include $(OBJECTS:.o=.d)

VPATH = $(BIOS_DIRECTORY):$(BIOS_DIRECTORY)/cmds:$(CPU_DIRECTORY)

%.o: %.c
	$(compile)

%.o: %.S
	$(assemble)

clean:
	$(RM) $(OBJECTS) boot.elf boot.bin *.map *.d

.PHONY: all clean
