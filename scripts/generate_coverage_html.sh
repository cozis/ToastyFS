#!/bin/bash
# Generate HTML coverage report using lcov

set -e

OUTPUT_DIR="coverage_report"

# Check if lcov is installed
if ! command -v lcov &> /dev/null; then
    echo "Error: lcov is not installed"
    echo "Please install it with: sudo apt-get install lcov"
    exit 1
fi

# Capture coverage data with branch coverage enabled
echo "Capturing coverage data..."
lcov --capture --directory . --output-file coverage.info --rc lcov_branch_coverage=1

# Filter out system headers if any exist
echo "Filtering coverage data..."
lcov --remove coverage.info '/usr/*' --output-file coverage.info --ignore-errors unused --rc lcov_branch_coverage=1 || cp coverage.info coverage.info.bak

# Generate HTML report
echo "Generating HTML report..."
genhtml coverage.info --output-directory "$OUTPUT_DIR" --branch-coverage --rc lcov_branch_coverage=1

# Clean up
rm -f coverage.info

echo "HTML report generated in $OUTPUT_DIR/"
echo "Open $OUTPUT_DIR/index.html in your browser"
