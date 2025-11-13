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
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-radius: 8px;
        }
        h1 {
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }
        h2 {
            color: #555;
            margin-top: 30px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #4CAF50;
            color: white;
            font-weight: bold;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .file-link {
            color: #2196F3;
            text-decoration: none;
            font-weight: 500;
        }
        .file-link:hover {
            text-decoration: underline;
        }
        .coverage-bar {
            height: 20px;
            background-color: #e0e0e0;
            border-radius: 10px;
            overflow: hidden;
            position: relative;
        }
        .coverage-fill {
            height: 100%;
            background-color: #4CAF50;
            transition: width 0.3s ease;
        }
        .coverage-low { background-color: #f44336; }
        .coverage-medium { background-color: #ff9800; }
        .coverage-high { background-color: #4CAF50; }
        .coverage-text {
            position: absolute;
            width: 100%;
            text-align: center;
            line-height: 20px;
            font-size: 12px;
            font-weight: bold;
            color: #333;
        }
        .summary {
            background-color: #e8f5e9;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }
        .summary h3 {
            margin-top: 0;
            color: #2e7d32;
        }
        .stat {
            font-size: 18px;
            margin: 10px 0;
        }
        code {
            background-color: #f5f5f5;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        .source-code {
            background-color: #f8f8f8;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.5;
        }
        .line-number {
            color: #999;
            display: inline-block;
            width: 50px;
            text-align: right;
            margin-right: 15px;
            user-select: none;
        }
        .branch-taken {
            background-color: #c8e6c9;
        }
        .branch-not-taken {
            background-color: #ffcdd2;
        }
        .branch-info {
            color: #666;
            font-size: 11px;
            margin-left: 10px;
            font-style: italic;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 Branch Coverage Report</h1>
        <p>Generated from random simulation coverage analysis</p>

        <div class="summary">
            <h3>Overall Coverage Summary</h3>
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

    # Determine coverage class
    if [ "$COVERAGE_PERCENT" -lt 30 ]; then
        COVERAGE_CLASS="coverage-low"
    elif [ "$COVERAGE_PERCENT" -lt 70 ]; then
        COVERAGE_CLASS="coverage-medium"
    else
        COVERAGE_CLASS="coverage-high"
    fi

    cat >> "$OUTPUT_DIR/index.html" <<HTMLSUMMARY
            <div class="stat">
                <strong>Total Branches:</strong> $TOTAL_BRANCHES<br>
                <strong>Branches Taken:</strong> $TAKEN_BRANCHES<br>
                <strong>Coverage:</strong> ${COVERAGE_PERCENT}%
            </div>
            <div class="coverage-bar">
                <div class="coverage-fill $COVERAGE_CLASS" style="width: ${COVERAGE_PERCENT}%"></div>
                <div class="coverage-text">${COVERAGE_PERCENT}%</div>
            </div>
        </div>

        <h2>Coverage by File</h2>
        <table>
            <tr>
                <th>File</th>
                <th>Branches Taken</th>
                <th>Total Branches</th>
                <th>Coverage</th>
                <th>Visual</th>
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

                if [ "$percentage" -lt 30 ]; then
                    bar_class="coverage-low"
                elif [ "$percentage" -lt 70 ]; then
                    bar_class="coverage-medium"
                else
                    bar_class="coverage-high"
                fi

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
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background-color: white; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); border-radius: 8px; }
        h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }
        .back-link { display: inline-block; margin-bottom: 20px; color: #2196F3; text-decoration: none; }
        .back-link:hover { text-decoration: underline; }
        pre { background-color: #f8f8f8; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Courier New', monospace; font-size: 13px; line-height: 1.8; margin: 0; }
        .line { display: block; }
        .line-number { color: #999; display: inline-block; width: 60px; text-align: right; margin-right: 20px; user-select: none; border-right: 2px solid #ddd; padding-right: 10px; }
        .exec-count { color: #666; display: inline-block; width: 60px; text-align: right; margin-right: 15px; font-size: 11px; }
        .branch-taken { background-color: #c8e6c9; }
        .branch-not-taken { background-color: #ffcdd2; }
        .branch-partial { background-color: #fff9c4; }
        .branch-info { color: #1565c0; font-weight: bold; margin-left: 5px; }
        .summary { background-color: #e8f5e9; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <a href="index.html" class="back-link">← Back to Summary</a>
        <h1>Coverage Report: $filename</h1>
        <div class="summary">
            <strong>Branches Taken:</strong> $taken / $branches ($percentage%)<br>
        </div>
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
    </div>
</body>
</html>
FILEFOOTER

                # Add row to main index
                cat >> "$OUTPUT_DIR/index.html" <<TABLEROW
            <tr>
                <td><a href="$file_html" class="file-link">$filename</a></td>
                <td>$taken</td>
                <td>$branches</td>
                <td>${percentage}%</td>
                <td>
                    <div class="coverage-bar">
                        <div class="coverage-fill $bar_class" style="width: ${percentage}%"></div>
                        <div class="coverage-text">${percentage}%</div>
                    </div>
                </td>
            </tr>
TABLEROW
            fi
        fi
    done

    # Close HTML
    cat >> "$OUTPUT_DIR/index.html" <<'HTMLFOOTER'
        </table>
    </div>
</body>
</html>
HTMLFOOTER

else
    cat >> "$OUTPUT_DIR/index.html" <<'HTMLFOOTER'
            <p>No branch coverage data found.</p>
        </div>
    </div>
</body>
</html>
HTMLFOOTER
fi

echo "HTML report generated in $OUTPUT_DIR/"
