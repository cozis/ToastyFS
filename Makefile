CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -ggdb -O0
AR      ?= ar

INCLUDES = -Iquakey/include -Iinclude -I.

# ---- Library (client-side only) ----

LIB_SRCS = src/client.c src/tcp.c src/byte_queue.c src/message.c src/basic.c
LIB_OBJS = $(LIB_SRCS:.c=.o)

STATIC_LIB = libtoastyfs.a
SHARED_LIB = libtoastyfs.so

# ---- Server binary ----

SERVER_SRCS = src/basic.c src/file_system.c src/byte_queue.c src/message.c \
              src/tcp.c src/server.c src/main.c src/log.c src/client_table.c \
              src/chunk_store.c src/metadata.c

# ---- Client binary (random test client) ----

CLIENT_SRCS = src/basic.c src/file_system.c src/byte_queue.c src/message.c \
              src/tcp.c src/server.c src/client.c src/random_client.c src/main.c \
              src/log.c src/client_table.c src/chunk_store.c src/metadata.c

# ---- Simulation binary ----

SIM_SRCS = src/basic.c src/file_system.c src/byte_queue.c src/message.c \
           src/tcp.c src/server.c src/client.c src/random_client.c src/main.c \
           src/log.c src/client_table.c src/invariant_checker.c src/chunk_store.c \
           src/metadata.c quakey/src/mockfs.c quakey/src/quakey.c

# ---- Default target ----

all: $(STATIC_LIB) $(SHARED_LIB) toastyfs toastyfs_client toastyfs_simulation

# ---- Library targets ----

lib: $(STATIC_LIB) $(SHARED_LIB)

$(STATIC_LIB): $(LIB_OBJS)
	$(AR) rcs $@ $^

$(SHARED_LIB): $(LIB_SRCS)
	$(CC) $(CFLAGS) -shared -fPIC $(INCLUDES) $^ -o $@

src/%.o: src/%.c
	$(CC) $(CFLAGS) $(INCLUDES) -fPIC -c $< -o $@

# ---- Binary targets ----

toastyfs: $(SERVER_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -DMAIN_SERVER $^ -o $@

toastyfs_client: $(CLIENT_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -DMAIN_CLIENT $^ -o $@

toastyfs_simulation: $(SIM_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) -DMAIN_SIMULATION -DFAULT_INJECTION $^ -o $@

# ---- Install ----

PREFIX    ?= /usr/local
LIBDIR    ?= $(PREFIX)/lib
INCLUDEDIR?= $(PREFIX)/include

install: $(STATIC_LIB) $(SHARED_LIB)
	install -d $(DESTDIR)$(LIBDIR)
	install -d $(DESTDIR)$(INCLUDEDIR)
	install -m 644 $(STATIC_LIB) $(DESTDIR)$(LIBDIR)/
	install -m 755 $(SHARED_LIB) $(DESTDIR)$(LIBDIR)/
	install -m 644 include/toastyfs.h $(DESTDIR)$(INCLUDEDIR)/

# ---- Clean ----

clean:
	rm -f $(LIB_OBJS) $(STATIC_LIB) $(SHARED_LIB)
	rm -f toastyfs toastyfs_client toastyfs_simulation

.PHONY: all lib clean install
