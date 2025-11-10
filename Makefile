
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
OFILES = $(CFILES:.c=.o)

.PHONY: all clean

all: mousefs$(EXT) mousefs_random_test$(EXT) example_client$(EXT) libmousefs.a

mousefs$(EXT): $(CFILES) $(HFILES)
	gcc -o $@ $(CFILES) $(CFLAGS) $(LFLAGS) -Iinc -DBUILD_SERVER

mousefs_random_test$(EXT): $(CFILES) $(HFILES)
	gcc -o $@ $(CFILES) $(CFLAGS) $(LFLAGS) -Iinc -DBUILD_TEST

example_client$(EXT): libmousefs.a
	gcc -o $@ examples/main.c $(CFLAGS) -lmousefs $(LFLAGS) -Iinc -L.

%.o: %.c $(HFILES)
	gcc -c -o $@ $< $(CFLAGS) -Iinc

libmousefs.a: $(OFILES)
	ar rcs $@ $^

clean:
	rm -f                       \
		mousefs.exe             \
		mousefs.out             \
		mousefs_random_test.exe \
		mousefs_random_test.out \
		example_client.exe      \
		example_client.out      \
		libmousefs.a
