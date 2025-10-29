
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

.PHONY: all clean

all: tinydfs_server$(EXT) tinydfs_test$(EXT) example_client$(EXT)

tinydfs_server$(EXT): $(CFILES) $(HFILES)
	gcc -o $@ $(CFILES) $(CFLAGS) $(LFLAGS) -Iinc -DBUILD_SERVER

tinydfs_test$(EXT): $(CFILES) $(HFILES)
	gcc -o $@ $(CFILES) $(CFLAGS) $(LFLAGS) -Iinc -DBUILD_TEST

example_client$(EXT): examples/main.c $(CFILES) $(HFILES)
	gcc -o $@ examples/main.c $(CFILES) $(CFLAGS) $(LFLAGS) -Iinc

clean:
	rm                     \
		tinydfs_server.exe \
		tinydfs_server.out \
		tinydfs_test.exe   \
		tinydfs_test.out   \
		example_client.exe \
		example_client.out
