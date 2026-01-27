#!/bin/bash
set -e

TEST_BINARY="toasty_test_coverage"
COVERAGE_DIR="coverage_html"

echo "=== Step 1: Building test with coverage instrumentation ==="
gcc src/sha256.c src/basic.c src/file_system.c src/byte_queue.c src/file_tree.c \
    src/message.c src/tcp.c src/wal.c src/hash_set.c src/client.c \
    src/metadata_server.c src/chunk_server.c src/random_client.c src/test_client.c src/main.c \
    quakey/src/mockfs.c quakey/src/quakey.c \
    -o "$TEST_BINARY" \
    -Iquakey/include -Iinclude \
    -Wall -Wextra -ggdb -O0 \
    -DMAIN_TEST \
    --coverage -fprofile-arcs -ftest-coverage
echo "Build complete: $TEST_BINARY"

echo ""
echo "=== Step 2: Running tests ==="
lcov --zerocounters --directory . --quiet
lcov --capture --initial --directory . --output-file coverage_base.info --rc lcov_branch_coverage=1 --quiet
"./$TEST_BINARY"
echo "Tests finished"

echo ""
echo "=== Step 3: Generating coverage report ==="
lcov --capture --directory . --output-file coverage_test.info --rc lcov_branch_coverage=1 --quiet
lcov --add-tracefile coverage_base.info --add-tracefile coverage_test.info --output-file coverage.info --rc lcov_branch_coverage=1 --quiet
lcov --remove coverage.info '/usr/*' 'quakey/*' --output-file coverage.info --rc lcov_branch_coverage=1 --quiet
genhtml coverage.info --output-directory "$COVERAGE_DIR" --branch-coverage --quiet
rm -f coverage_base.info coverage_test.info

echo ""
echo "=== Done ==="
echo "Coverage report: $COVERAGE_DIR/index.html"
