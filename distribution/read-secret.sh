#!/bin/bash
# Decrypts a secret from distribution/secrets/<NAME>.age.
# Uses keytap locally; falls back to age + AGE_SECRET_KEY in CI.
#
# Usage:
#   ./distribution/read-secret.sh SECRET_NAME

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 SECRET_NAME" >&2
    exit 1
fi

SECRET_NAME="${1%.age}"
SECRET_PATH="$SCRIPT_DIR/secrets/$SECRET_NAME.age"

if [ ! -f "$SECRET_PATH" ]; then
    echo "Error: Secret file not found: $SECRET_PATH" >&2
    exit 1
fi

if [ -n "${AGE_SECRET_KEY:-}" ]; then
    printf '%s\n' "$AGE_SECRET_KEY" | age -d -i - "$SECRET_PATH"
elif command -v keytap &>/dev/null; then
    keytap decrypt keytap < "$SECRET_PATH"
else
    echo "Error: Neither AGE_SECRET_KEY nor keytap is available" >&2
    exit 1
fi
