CC ?= cc
CFLAGS ?= -Wall -Wextra -O2 -std=c11 -D_POSIX_C_SOURCE=200809L
LDFLAGS ?=
LDLIBS ?= -lssl -lcrypto
OPENSSL_PREFIX ?=

ifeq ($(OPENSSL_PREFIX),)
ifneq ($(wildcard /opt/homebrew/opt/openssl@3/include/openssl/evp.h),)
OPENSSL_PREFIX := /opt/homebrew/opt/openssl@3
else ifneq ($(wildcard /usr/local/opt/openssl@3/include/openssl/evp.h),)
OPENSSL_PREFIX := /usr/local/opt/openssl@3
endif
endif

ifneq ($(OPENSSL_PREFIX),)
CFLAGS += -I$(OPENSSL_PREFIX)/include
LDFLAGS += -L$(OPENSSL_PREFIX)/lib
endif

OBJS = main.o util.o net.o crypto.o protocol.o

.PHONY: all clean

all: secure_chat

secure_chat: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(OBJS) secure_chat
