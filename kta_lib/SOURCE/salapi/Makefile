CROSS_COMPILE ?= 
CC:= $(CROSS_COMPILE)gcc
AR:= $(CROSS_COMPILE)ar

CFLAGS += -DENABLE_CFG
CFLAGS += -DMBEDTLS_PSA_CRYPTO_BUILTIN_KEYS
#CFLAGS += -DLOG_SAL_ENABLE

LIB :=libsal.a

INC += -I ../../include -I ../../../COMMON/logmodule/include -I ../include -I include -I extra_includes -I include/mbedtls/include

SRCS := \
	k_sal_crypto.c \
	k_sal_storage.c \
	k_sal_object.c \
	k_sal_rot.c \
    k_sal_log.c


SOURCES := $(wildcard $(SRCS))
OBJECTS := $(patsubst %.c,%.o,$(SOURCES))

CFLAGS +=$(INC)

.PHONY: all

all: $(LIB)

$(LIB): $(OBJECTS)
	$(AR) -r $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -Os -c $^ -o $@

clean:
	rm -f $(OBJECTS) $(LIB)


