#!/bin/bash
# Fix line endings for coverage scripts

echo "Fixing line endings for coverage scripts..."

# Convert CRLF to LF
dos2unix scripts/measure_coverage.sh 2>/dev/null || sed -i 's/\r$//' scripts/measure_coverage.sh
dos2unix scripts/generate_coverage_html.sh 2>/dev/null || sed -i 's/\r$//' scripts/generate_coverage_html.sh

# Ensure execute permissions
chmod +x scripts/measure_coverage.sh
chmod +x scripts/generate_coverage_html.sh

echo "Done! Line endings fixed and execute permissions set."
echo ""
echo "You can now run:"
echo "  make coverage-report"
echo "  make coverage-html"
