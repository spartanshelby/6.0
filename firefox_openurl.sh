#!/bin/bash

# Default values
CONCURRENT_REQUESTS=5
TIMEOUT_SECONDS=30
INPUT_FILE=""
URLS=""

# Function to display usage
usage() {
    echo "Usage: $0 [-r concurrent_requests] [-w timeout_seconds] [-f input_file] [urls...]"
    echo "  -r  Number of concurrent requests (default: 5)"
    echo "  -w  Timeout in seconds (default: 30)"
    echo "  -f  Input file containing URLs (one per line)"
    echo "  If no -f flag, provide URLs as arguments or pipe via stdin"
    echo ""
    echo "Examples:"
    echo "  $0 -r 10 -w 60 -f urls.txt"
    echo "  $0 -r 3 https://example1.com https://example2.com"
    echo "  cat urls.txt | $0 -r 8 -w 45"
    exit 1
}

# Parse command line arguments
while getopts "r:w:f:h" opt; do
    case $opt in
        r) CONCURRENT_REQUESTS="$OPTARG" ;;
        w) TIMEOUT_SECONDS="$OPTARG" ;;
        f) INPUT_FILE="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Shift to get remaining arguments (URLs)
shift $((OPTIND-1))

# Function to open a single URL in Firefox with timeout
open_url() {
    local url="$1"
    # Clean the URL (remove leading/trailing whitespace)
    url=$(echo "$url" | xargs)
    
    # Skip empty lines
    if [ -z "$url" ]; then
        return
    fi
    
    # Add http:// prefix if no protocol specified
    if [[ ! "$url" =~ ^https?:// ]]; then
        url="http://$url"
    fi
    
    echo "Opening: $url"
    
    # Open in Firefox ESR with timeout
    timeout "${TIMEOUT_SECONDS}s" firefox-esr --new-tab "$url" 2>/dev/null
    
    # Small delay between requests
    sleep 16
}

# Export function for parallel execution
export -f open_url
export TIMEOUT_SECONDS

# Collect URLs
URL_LIST=""

if [ -n "$INPUT_FILE" ]; then
    # Read from input file
    if [ ! -f "$INPUT_FILE" ]; then
        echo "Error: Input file '$INPUT_FILE' not found!"
        exit 1
    fi
    URL_LIST=$(cat "$INPUT_FILE")
elif [ -p /dev/stdin ] || [ ! -t 0 ]; then
    # Read from stdin (pipe or redirection)
    URL_LIST=$(cat)
elif [ $# -gt 0 ]; then
    # Read from command line arguments
    URL_LIST=$(printf "%s\n" "$@")
else
    echo "Error: No URLs provided!"
    usage
fi

# Check if we have URLs
if [ -z "$URL_LIST" ]; then
    echo "Error: No URLs to process!"
    exit 1
fi

echo "Starting Firefox ESR with:"
echo "  Concurrent requests: $CONCURRENT_REQUESTS"
echo "  Timeout per request: ${TIMEOUT_SECONDS} seconds"
echo "  Total URLs: $(echo "$URL_LIST" | wc -l | xargs)"

# Process URLs in parallel
echo "$URL_LIST" | xargs -P "$CONCURRENT_REQUESTS" -I {} bash -c 'open_url "{}"'

echo "All URLs processed!"
