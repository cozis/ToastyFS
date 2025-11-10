
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

all: mousefs_server$(EXT) mousefs_test$(EXT) example_client$(EXT)

mousefs_server$(EXT): $(CFILES) $(HFILES)
	gcc -o $@ $(CFILES) $(CFLAGS) $(LFLAGS) -Iinc -DBUILD_SERVER

mousefs_test$(EXT): $(CFILES) $(HFILES)
	gcc -o $@ $(CFILES) $(CFLAGS) $(LFLAGS) -Iinc -DBUILD_TEST

example_client$(EXT): examples/main.c $(CFILES) $(HFILES)
	gcc -o $@ examples/main.c $(CFILES) $(CFLAGS) $(LFLAGS) -Iinc

clean:
	rm                     \
		mousefs_server.exe \
		mousefs_server.out \
		mousefs_test.exe   \
		mousefs_test.out   \
		example_client.exe \
		example_client.out
