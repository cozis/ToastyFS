#!/bin/bash
set -e

# Build simulation with branch coverage instrumentation
gcc src/sha256.c src/basic.c src/file_system.c src/byte_queue.c src/file_tree.c src/message.c src/tcp.c src/wal.c src/hash_set.c src/client.c src/metadata_server.c src/chunk_server.c src/random_client.c src/main.c quakey/src/lfs.c quakey/src/lfs_util.c quakey/src/quakey.c -o toasty_simulation_coverage -Iquakey/include -Iinclude -Wall -Wextra -ggdb -O0 -DMAIN_SIMULATION --coverage -fprofile-arcs -ftest-coverage

echo "Coverage build complete: toasty_simulation_coverage"
echo ""
echo "To generate HTML coverage report:"
echo "  1. Run: ./toasty_simulation_coverage"
echo "  2. Run: ./build_coverage.sh --report"

if [ "$1" = "--report" ]; then
    # Reset previous coverage data
    lcov --zerocounters --directory .

    # Capture baseline coverage (before running)
    lcov --capture --initial --directory . --output-file coverage_base.info --rc lcov_branch_coverage=1

    # Run the simulation with a 60 second time limit
    # Use SIGINT for graceful shutdown (allows coverage data to be flushed)
    # Falls back to SIGKILL after 5 seconds if process doesn't exit
    echo "Running simulation (60 second limit)..."
    timeout --signal=INT --kill-after=5 60 ./toasty_simulation_coverage || true

    # Capture coverage after running
    lcov --capture --directory . --output-file coverage_test.info --rc lcov_branch_coverage=1

    # Combine baseline and test coverage
    lcov --add-tracefile coverage_base.info --add-tracefile coverage_test.info --output-file coverage.info --rc lcov_branch_coverage=1

    # Remove external/system headers from report
    lcov --remove coverage.info '/usr/*' --output-file coverage.info --rc lcov_branch_coverage=1

    # Generate HTML report
    genhtml coverage.info --output-directory coverage_html --branch-coverage

    echo ""
    echo "HTML coverage report generated in: coverage_html/index.html"
fi
