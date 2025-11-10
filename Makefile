
CFLAGS = -Wall -Wextra -ggdb

ifeq ($(OS),Windows_NT)
	LFLAGS = -lws2_32
	EXT = .exe
else
	LFLAGS =
	EXT = .out
endif

CFILES = $(shell find src -name '*.c')
HFILES = $(shell find src -name '*.h')

# Client library source files
CLIENT_CFILES = src/client.c src/basic.c src/tcp.c src/message.c
CLIENT_OFILES = $(CLIENT_CFILES:.c=.o)

.PHONY: all clean

all: mousefs_server$(EXT) mousefs_test$(EXT) example_client$(EXT) libmousefs_client.a

mousefs_server$(EXT): $(CFILES) $(HFILES)
	gcc -o $@ $(CFILES) $(CFLAGS) $(LFLAGS) -Iinc -DBUILD_SERVER

mousefs_test$(EXT): $(CFILES) $(HFILES)
	gcc -o $@ $(CFILES) $(CFLAGS) $(LFLAGS) -Iinc -DBUILD_TEST

example_client$(EXT): examples/main.c $(CFILES) $(HFILES)
	gcc -o $@ examples/main.c $(CFILES) $(CFLAGS) $(LFLAGS) -Iinc

# Client library build rules
%.o: %.c $(HFILES)
	gcc -c -o $@ $< $(CFLAGS) -Iinc

libmousefs_client.a: $(CLIENT_OFILES)
	ar rcs $@ $^

clean:
	rm -f                  \
		mousefs_server.exe \
		mousefs_server.out \
		mousefs_test.exe   \
		mousefs_test.out   \
		example_client.exe \
		example_client.out \
		libmousefs_client.a \
		$(CLIENT_OFILES)
