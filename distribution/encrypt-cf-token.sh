#!/bin/bash
# Encrypts a Cloudflare API token and stores it as an age-encrypted secret.
#
# Usage:
#   echo "your-api-token" | ./distribution/encrypt-cf-token.sh
#   CLOUDFLARE_API_TOKEN=your-token ./distribution/encrypt-cf-token.sh
#
# Creates: secrets/CLOUDFLARE_API_TOKEN.age

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RECIPIENTS="$PROJECT_ROOT/secrets/age-recipients.txt"
OUTPUT="$PROJECT_ROOT/secrets/CLOUDFLARE_API_TOKEN.age"

if [ ! -f "$RECIPIENTS" ]; then
    echo "error: $RECIPIENTS not found" >&2
    exit 1
fi

# Read token from env var or stdin
if [ -n "$CLOUDFLARE_API_TOKEN" ]; then
    TOKEN="$CLOUDFLARE_API_TOKEN"
else
    echo "Paste your Cloudflare API token (then press Enter):" >&2
    read -r TOKEN
fi

if [ -z "$TOKEN" ]; then
    echo "error: no token provided" >&2
    exit 1
fi

# Build recipient args
RECIPIENT_ARGS=""
while IFS= read -r line; do
    line="$(echo "$line" | sed 's/#.*//' | xargs)"
    [ -z "$line" ] && continue
    RECIPIENT_ARGS="$RECIPIENT_ARGS -r $line"
done < "$RECIPIENTS"

printf '%s' "$TOKEN" | age $RECIPIENT_ARGS -o "$OUTPUT"

echo "Encrypted token saved to $OUTPUT"
echo "To decrypt: age -d -i <key-file> $OUTPUT"
