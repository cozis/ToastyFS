
CFLAGS = -Wall -Wextra -ggdb

ifeq ($(OS),Windows_NT)
	LFLAGS = -lws2_32
	EXT = .exe
else
	LFLAGS =
	EXT = .out
endif

.PHONY: all clean

all: metadata_server$(EXT) chunk_server$(EXT) example$(EXT)

metadata_server$(EXT): TinyDFS.c TinyDFS.h
	gcc -o $@ TinyDFS.c -DBUILD_METADATA_SERVER $(CFLAGS) $(LFLAGS)

chunk_server$(EXT): TinyDFS.c TinyDFS.h
	gcc -o $@ TinyDFS.c -DBUILD_CHUNK_SERVER $(CFLAGS) $(LFLAGS)

example$(EXT): examples/main.c TinyDFS.c TinyDFS.h
	gcc -o $@ examples/main.c TinyDFS.c $(CFLAGS) $(LFLAGS) -I.

clean:
	rm                      \
		metadata_server.exe \
		matadata_server.out \
		chunk_server.exe    \
		chunk_server.out    \
		example.exe         \
		example.out
