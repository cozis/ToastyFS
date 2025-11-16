
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

.PHONY: all clean coverage coverage-report coverage-html

all: toastyfs$(EXT) toastyfs_random_test$(EXT) example_client$(EXT) libtoastyfs.a

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

example_client$(EXT): libtoastyfs.a
	gcc -o $@ examples/main.c $(CFLAGS) -ltoastyfs $(LFLAGS) -Iinc -L.

%.o: %.c $(HFILES)
	gcc -c -o $@ $< $(CFLAGS) -Iinc

libtoastyfs.a: $(OFILES)
	ar rcs $@ $^

clean:
	rm -f                                \
		toastyfs.exe                      \
		toastyfs.out                      \
		toastyfs_random_test.exe          \
		toastyfs_random_test.out          \
		toastyfs_random_test_coverage.exe \
		toastyfs_random_test_coverage.out \
		example_client.exe               \
		example_client.out               \
		libtoastyfs.a                     \
		src/*.o                          \
		src/*.gcda                       \
		src/*.gcno                       \
		*.gcda                           \
		*.gcno
