
CFLAGS = -Wall -Wextra -ggdb
COVERAGE_CFLAGS = $(CFLAGS) --coverage
COVERAGE_LFLAGS = --coverage

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

WEB_CFILES = $(shell find web/src web/3p -name '*.c')
WEB_HFILES = $(shell find web/src web/3p -name '*.h')

.PHONY: all clean coverage coverage-report coverage-html

all: toastyfs$(EXT) toastyfs_web$(EXT) toastyfs_random_test$(EXT) example_async_api$(EXT) example_blocking_api$(EXT) libtoastyfs.a

coverage: toastyfs_random_test_coverage$(EXT)

coverage-report:
	@./scripts/measure_coverage.sh 60

coverage-html:
	@./scripts/measure_coverage.sh 60 --html

toastyfs$(EXT): $(CFILES) $(HFILES)
	gcc -o $@ $(CFILES) $(CFLAGS) $(LFLAGS) -Iinc -DBUILD_SERVER

toastyfs_random_test$(EXT): $(CFILES) $(HFILES)
	gcc -o $@ $(CFILES) $(CFLAGS) $(LFLAGS) -Iinc -DBUILD_TEST

toastyfs_random_test_coverage$(EXT): $(CFILES) $(HFILES)
	gcc -o $@ $(CFILES) $(COVERAGE_CFLAGS) $(LFLAGS) $(COVERAGE_LFLAGS) -Iinc -DBUILD_TEST

example_async_api$(EXT): libtoastyfs.a examples/async_api.c
	gcc -o $@ examples/async_api.c $(CFLAGS) -ltoastyfs $(LFLAGS) -Iinc -L.

example_blocking_api$(EXT): libtoastyfs.a examples/blocking_api.c
	gcc -o $@ examples/blocking_api.c $(CFLAGS) -ltoastyfs $(LFLAGS) -Iinc -L.

toastyfs_web$(EXT): libtoastyfs.a $(WEB_CFILES) $(WEB_HFILES)
	gcc -o $@ $(WEB_CFILES) $(CFLAGS) -ltoastyfs $(LFLAGS) -Iinc -Iweb/3p -L.

%.o: %.c $(HFILES)
	gcc -c -o $@ $< $(CFLAGS) -Iinc

libtoastyfs.a: $(OFILES)
	ar rcs $@ $^

clean:
	rm -f          \
		*.exe      \
		*.out      \
		*.a        \
		*.gcov     \
		src/*.o    \
		src/*.gcda \
		src/*.gcno \
		*.gcda     \
		*.gcno
