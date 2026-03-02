#!/bin/bash

# YARA Web Malware Scanner
# Scans a target directory or file with all web malware YARA rules

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
RULES_DIR="${SCRIPT_DIR}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="scan_${TIMESTAMP}.log"

# Default values
TARGET=""
RECURSIVE=false
VERBOSE=false
OUTPUT_FORMAT="json"
THREADS=1

# Functions
print_usage() {
    echo "Usage: $0 [OPTIONS] <target>"
    echo ""
    echo "Options:"
    echo "  -r, --recursive          Scan directories recursively"
    echo "  -v, --verbose            Verbose output"
    echo "  -f, --format FORMAT      Output format: json (default), txt, csv"
    echo "  -t, --threads N          Number of parallel threads"
    echo "  -o, --output FILE        Write results to file"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 /path/to/file.php"
    echo "  $0 -r /path/to/web/directory"
    echo "  $0 -r -f csv /path/to/samples"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -r|--recursive)
            RECURSIVE=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -f|--format)
            OUTPUT_FORMAT="$2"
            shift 2
            ;;
        -t|--threads)
            THREADS="$2"
            shift 2
            ;;
        -o|--output)
            LOG_FILE="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        -*)
            echo "Unknown option: $1"
            print_usage
            exit 1
            ;;
        *)
            TARGET="$1"
            shift
            ;;
    esac
done

# Validate inputs
if [ -z "$TARGET" ]; then
    echo -e "${RED}[!] Error: Target path required${NC}"
    print_usage
    exit 1
fi

if [ ! -e "$TARGET" ]; then
    echo -e "${RED}[!] Error: Target does not exist: $TARGET${NC}"
    exit 1
fi

# Check if yara is installed and determine version
if ! command -v yara &> /dev/null; then
    echo -e "${RED}[!] Error: yara not found. Please install yara first.${NC}"
    exit 1
fi

# query yara version so we can decide whether -J is supported
YARA_VERSION=$(yara --version 2>/dev/null || echo "0")
# strip anything but the major number
YARA_MAJOR=$(echo "$YARA_VERSION" | cut -d. -f1)

# determine whether the binary actually understands -J by running a dry test
YARA_HAS_JSON=true
if yara -J /dev/null 2>&1 | grep -q "unknown option"; then
    YARA_HAS_JSON=false
fi

# if the user requested json output but the version is too old *or* the
# binary doesn't accept -J, warn and fall back to plain text
if [ "$OUTPUT_FORMAT" = "json" ] && (
       [ "$YARA_MAJOR" -lt 4 ] || [ "$YARA_HAS_JSON" = false ]); then
    echo -e "${YELLOW}[!] installed yara ($YARA_VERSION) does not support JSON output; using plain format instead${NC}"
    OUTPUT_FORMAT="txt"
fi

# Print header
echo -e "${BLUE}================================${NC}"
echo -e "${BLUE}YARA Web Malware Scanner${NC}"
echo -e "${BLUE}================================${NC}"
echo ""
echo -e "${BLUE}[*] Target: $TARGET${NC}"
echo -e "${BLUE}[*] Recursive: $RECURSIVE${NC}"
echo -e "${BLUE}[*] Output format: $OUTPUT_FORMAT${NC}"
echo -e "${BLUE}[*] Threads: $THREADS${NC}"
echo -e "${BLUE}[*] Log file: $LOG_FILE${NC}"
echo ""

# Build yara command
YARA_CMD="yara"

# Add recursive flag if needed
if [ "$RECURSIVE" = true ]; then
    YARA_CMD="$YARA_CMD -r"
fi

# Add output format
case $OUTPUT_FORMAT in
    json)
        # -J only available in yara 4.x and later; we already checked above
        YARA_CMD="$YARA_CMD -J"
        ;;
    csv)
        # CSV not directly supported by yara, will format manually
        ;;
esac

# Add verbose flag
if [ "$VERBOSE" = true ]; then
    YARA_CMD="$YARA_CMD -v"
fi

# Add all rule files
for rule_file in "$RULES_DIR"/*.yar; do
    if [ -f "$rule_file" ]; then
        YARA_CMD="$YARA_CMD \"$rule_file\""
    fi
done

# Add target
YARA_CMD="$YARA_CMD \"$TARGET\""

echo -e "${BLUE}[*] Starting scan...${NC}"
echo ""

# Run scan and capture output
scan_output=$(eval "$YARA_CMD" 2>&1 || true)
detection_count=$(echo "$scan_output" | grep -c "0x" || echo "0")

# Process output
if [ -z "$scan_output" ] || [ "$scan_output" == "" ]; then
    echo -e "${GREEN}[✓] No detections found${NC}"
    echo "0" > "$LOG_FILE"
else
    echo -e "${RED}[!] Detections found:${NC}"
    echo ""
    echo "$scan_output" | head -50
    
    if [ $(echo "$scan_output" | wc -l) -gt 50 ]; then
        echo ""
        echo -e "${YELLOW}... and more (see full results in $LOG_FILE)${NC}"
    fi
    
    # Save to log file
    echo "$scan_output" > "$LOG_FILE"
    echo ""
    echo -e "${BLUE}[*] Total matches: $detection_count${NC}"
fi

echo ""
echo -e "${BLUE}[*] Scan complete${NC}"
echo -e "${BLUE}[*] Results saved to: $LOG_FILE${NC}"
