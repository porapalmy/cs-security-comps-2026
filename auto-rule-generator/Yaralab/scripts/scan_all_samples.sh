#!/bin/bash

# Base directory containing generated rule folders
BASE_DIR="/home/ubuntu/yara-lab/rule_library/generated"

# Output combined file
OUTPUT_FILE="/home/ubuntu/yara-lab/rule_library/combined_generated_rules.yar"

# Clear output file if it already exists
> "$OUTPUT_FILE"

echo "[+] Combining YARA rules from: $BASE_DIR"
echo "[+] Output file: $OUTPUT_FILE"
echo ""

# Find all .yar and .yara files recursively
find "$BASE_DIR" -type f \( -iname "*.yar" -o -iname "*.yara" \) | while read -r file
do
    echo "[+] Adding: $file"

    echo "" >> "$OUTPUT_FILE"
    echo "/* ===================== */" >> "$OUTPUT_FILE"
    echo "/* Source: $file */" >> "$OUTPUT_FILE"
    echo "/* ===================== */" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"

    cat "$file" >> "$OUTPUT_FILE"
    echo "" >> "$OUTPUT_FILE"

done

echo ""
echo "[✓] Done. Combined rules written to:"
echo "$OUTPUT_FILE"