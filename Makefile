CC ?= cc
CFLAGS ?= -Wall -Wextra -O2 -std=c11 -D_POSIX_C_SOURCE=200809L
LDFLAGS ?=
LDLIBS ?= -lssl -lcrypto

OBJS = main.o util.o net.o crypto.o protocol.o

all: secure_chat

secure_chat: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(OBJS) secure_chat
