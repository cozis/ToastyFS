#!/bin/bash
# Script to measure branch coverage of the random simulation

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Branch Coverage Measurement Tool${NC}"
echo -e "${BLUE}========================================${NC}"
echo

# Clean previous coverage data
echo -e "${YELLOW}Cleaning previous coverage data...${NC}"
rm -f src/*.gcda src/*.gcno *.gcda *.gcno
make clean > /dev/null 2>&1

# Build with coverage
echo -e "${YELLOW}Building with coverage instrumentation...${NC}"
make coverage

# Run the simulation for a limited time
echo -e "${YELLOW}Running simulation...${NC}"
SIMULATION_TIME=${1:-5}  # Default to 5 seconds if not specified
echo "Running for ${SIMULATION_TIME} seconds..."

# Run simulation in background and kill it after specified time
timeout ${SIMULATION_TIME}s ./toastyfs_random_test_coverage.out || true

# Generate coverage reports
echo
echo -e "${YELLOW}Generating coverage reports...${NC}"

# Find all .gcda files and generate coverage reports
GCDA_FILES=$(find . -name "*.gcda")

TOTAL_BRANCHES=0
TAKEN_BRANCHES=0

# Generate gcov reports from the coverage data files
for gcda_file in $GCDA_FILES; do
    # Extract the source file name from the gcda filename
    # Files are named like: toastyfs_random_test_coverage.out-basic.gcda
    basename=$(basename "$gcda_file" .gcda)
    source_name=${basename#*-}  # Remove prefix up to and including '-'

    # Run gcov to generate the .gcov file
    gcov -b "$gcda_file" > /dev/null 2>&1 || true
done

# Parse gcov output to count branches
echo
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Branch Coverage Summary${NC}"
echo -e "${BLUE}========================================${NC}"
echo

# Process each .gcov file
for gcov_file in *.c.gcov; do
    if [ -f "$gcov_file" ]; then
        # Extract branch statistics from the gcov file
        branches=$(grep -c "^branch" "$gcov_file" 2>/dev/null)
        if [ -z "$branches" ]; then branches=0; fi

        if [ "$branches" -gt 0 ]; then
            taken_count=$(grep "^branch" "$gcov_file" 2>/dev/null | grep -c "taken [1-9]" 2>/dev/null || echo "0")
            # Clean up the value - remove any whitespace/newlines
            taken_count=$(echo "$taken_count" | tr -d '[:space:]')
            if [ -z "$taken_count" ] || [ "$taken_count" = "" ]; then taken_count=0; fi

            TOTAL_BRANCHES=$((TOTAL_BRANCHES + branches))
            TAKEN_BRANCHES=$((TAKEN_BRANCHES + taken_count))
            percentage=$((taken_count * 100 / branches))
            filename=$(echo "$gcov_file" | sed 's/.gcov$//')
            printf "%-40s %5d / %5d branches (%3d%%)\n" "$filename" "$taken_count" "$branches" "$percentage"
        fi
    fi
done

echo
echo -e "${BLUE}========================================${NC}"
if [ "$TOTAL_BRANCHES" -gt 0 ]; then
    COVERAGE_PERCENT=$((TAKEN_BRANCHES * 100 / TOTAL_BRANCHES))
    echo -e "${GREEN}Total: $TAKEN_BRANCHES / $TOTAL_BRANCHES branches reached (${COVERAGE_PERCENT}%)${NC}"
else
    echo -e "${YELLOW}No branch coverage data found${NC}"
fi
echo -e "${BLUE}========================================${NC}"
echo

# Generate HTML report if requested
if [ "$2" == "--html" ]; then
    echo -e "${YELLOW}Generating HTML coverage report...${NC}"
    # Get the directory where this script is located
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    "$SCRIPT_DIR/generate_coverage_html.sh"
    echo -e "${GREEN}HTML report generated in coverage_report/index.html${NC}"
    echo "Open with: firefox coverage_report/index.html (or your preferred browser)"
    echo
fi

# Clean up gcov files unless HTML was requested
if [ "$2" != "--html" ] && [ "$2" != "--detailed" ]; then
    echo -e "${YELLOW}Cleaning up coverage files...${NC}"
    rm -f *.gcov
fi

echo
echo -e "${GREEN}Coverage measurement complete!${NC}"
