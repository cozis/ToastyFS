#!/bin/bash
# Generate HTML coverage report from gcov files

set -e

OUTPUT_DIR="coverage_report"
mkdir -p "$OUTPUT_DIR"

# Create main index.html
cat > "$OUTPUT_DIR/index.html" <<'HTMLHEADER'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Branch Coverage Report</title>
    <style>
        body { font-family: sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f0f0f0; }
        .branch-taken { background-color: #d4edda; }
        .branch-not-taken { background-color: #f8d7da; }
    </style>
</head>
<body>
    <h1>Branch Coverage Report</h1>
    <p>Generated from random simulation coverage analysis</p>

    <h2>Overall Coverage Summary</h2>
HTMLHEADER

# Calculate totals
TOTAL_BRANCHES=0
TAKEN_BRANCHES=0

for gcov_file in *.c.gcov; do
    if [ -f "$gcov_file" ]; then
        branches=$(grep -c "^branch" "$gcov_file" 2>/dev/null || echo "0")
        if [ "$branches" -gt 0 ]; then
            taken=$(grep "^branch" "$gcov_file" 2>/dev/null | grep -c "taken [1-9]" 2>/dev/null || echo "0")
            taken=$(echo "$taken" | tr -d '[:space:]')
            if [ -z "$taken" ]; then taken=0; fi

            TOTAL_BRANCHES=$((TOTAL_BRANCHES + branches))
            TAKEN_BRANCHES=$((TAKEN_BRANCHES + taken))
        fi
    fi
done

if [ "$TOTAL_BRANCHES" -gt 0 ]; then
    COVERAGE_PERCENT=$((TAKEN_BRANCHES * 100 / TOTAL_BRANCHES))

    cat >> "$OUTPUT_DIR/index.html" <<HTMLSUMMARY
    <p>
        <strong>Total Branches:</strong> $TOTAL_BRANCHES<br>
        <strong>Branches Taken:</strong> $TAKEN_BRANCHES<br>
        <strong>Coverage:</strong> ${COVERAGE_PERCENT}%
    </p>

    <h2>Coverage by File</h2>
    <table>
        <tr>
            <th>File</th>
            <th>Branches Taken</th>
            <th>Total Branches</th>
            <th>Coverage %</th>
        </tr>
HTMLSUMMARY

    # Generate table rows for each file
    for gcov_file in *.c.gcov; do
        if [ -f "$gcov_file" ]; then
            filename=$(echo "$gcov_file" | sed 's/.gcov$//')
            branches=$(grep -c "^branch" "$gcov_file" 2>/dev/null || echo "0")

            if [ "$branches" -gt 0 ]; then
                taken=$(grep "^branch" "$gcov_file" 2>/dev/null | grep -c "taken [1-9]" 2>/dev/null || echo "0")
                taken=$(echo "$taken" | tr -d '[:space:]')
                if [ -z "$taken" ]; then taken=0; fi

                percentage=$((taken * 100 / branches))

                # Generate individual file report
                file_html="${filename}.html"
                echo "Generating report for $filename..."

                cat > "$OUTPUT_DIR/$file_html" <<FILEHEADER
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Coverage: $filename</title>
    <style>
        body { font-family: sans-serif; margin: 20px; }
        pre { background-color: #f5f5f5; padding: 10px; overflow-x: auto; font-family: monospace; font-size: 12px; }
        .line { display: block; }
        .line-number { color: #666; display: inline-block; width: 50px; text-align: right; margin-right: 10px; }
        .exec-count { color: #666; display: inline-block; width: 50px; text-align: right; margin-right: 10px; }
        .branch-taken { background-color: #d4edda; }
        .branch-not-taken { background-color: #f8d7da; }
        .branch-info { color: #666; font-size: 10px; }
    </style>
</head>
<body>
    <p><a href="index.html">← Back to Summary</a></p>
    <h1>Coverage: $filename</h1>
    <p><strong>Branches Taken:</strong> $taken / $branches ($percentage%)</p>
    <pre>
FILEHEADER

                # Process the gcov file and add source code with branch info
                awk '
                    /^branch/ {
                        branch_info = branch_info " " $0
                        next
                    }
                    /^        / {
                        # Line with execution count
                        line_num = $2
                        gsub(/:/, "", line_num)
                        exec_count = $1
                        gsub(/^[ \t]+/, "", exec_count)

                        # Get the actual source line
                        line_content = substr($0, index($0, $3))

                        # Determine background color based on branch coverage
                        bg_class = ""
                        if (branch_info != "") {
                            if (branch_info ~ /taken 0/) {
                                bg_class = "branch-not-taken"
                            } else if (branch_info ~ /never executed/) {
                                bg_class = "branch-not-taken"
                            } else {
                                bg_class = "branch-taken"
                            }
                        }

                        # Format execution count
                        if (exec_count == "-") {
                            exec_str = "-"
                        } else if (exec_count == "#####") {
                            exec_str = "0"
                            if (bg_class == "") bg_class = "branch-not-taken"
                        } else {
                            exec_str = exec_count
                        }

                        printf "<span class=\"line %s\"><span class=\"line-number\">%s</span><span class=\"exec-count\">%s</span>%s", bg_class, line_num, exec_str, line_content

                        if (branch_info != "") {
                            printf "<span class=\"branch-info\">%s</span>", branch_info
                        }
                        printf "</span>\n"

                        branch_info = ""
                    }
                ' "$gcov_file" >> "$OUTPUT_DIR/$file_html"

                cat >> "$OUTPUT_DIR/$file_html" <<'FILEFOOTER'
</pre>
</body>
</html>
FILEFOOTER

                # Add row to main index
                cat >> "$OUTPUT_DIR/index.html" <<TABLEROW
        <tr>
            <td><a href="$file_html">$filename</a></td>
            <td>$taken</td>
            <td>$branches</td>
            <td>${percentage}%</td>
        </tr>
TABLEROW
            fi
        fi
    done

    # Close HTML
    cat >> "$OUTPUT_DIR/index.html" <<'HTMLFOOTER'
    </table>
</body>
</html>
HTMLFOOTER

else
    cat >> "$OUTPUT_DIR/index.html" <<'HTMLFOOTER'
    <p>No branch coverage data found.</p>
</body>
</html>
HTMLFOOTER
fi

echo "HTML report generated in $OUTPUT_DIR/"
