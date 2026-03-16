#!/bin/bash
# Notarize and staple a macOS app bundle.
# Usage: ./distribution/notarize.sh Tapkey.app
set -euo pipefail

BUNDLE="${1:?Usage: notarize.sh <bundle>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

AGE_KEY=$("$SCRIPT_DIR/get-age-key.sh") || { echo "Notarization skipped (secrets unavailable)"; exit 0; }

TMPDIR_TK=$(mktemp -d)
trap 'rm -rf "$TMPDIR_TK"' EXIT

printf '%s' "$AGE_KEY" > "$TMPDIR_TK/age-key.txt"
age -d -i "$TMPDIR_TK/age-key.txt" "$SCRIPT_DIR/../secrets/NOTARY_KEY_BASE64.age" \
  | base64 --decode > "$TMPDIR_TK/auth_key.p8"
NOTARY_KEY_ID=$(age -d -i "$TMPDIR_TK/age-key.txt" "$SCRIPT_DIR/../secrets/NOTARY_KEY_ID.age")
NOTARY_ISSUER_ID=$(age -d -i "$TMPDIR_TK/age-key.txt" "$SCRIPT_DIR/../secrets/NOTARY_ISSUER_ID.age")
rm -f "$TMPDIR_TK/age-key.txt"

ditto -c -k --keepParent "$BUNDLE" "$TMPDIR_TK/notarize.zip"

xcrun notarytool submit "$TMPDIR_TK/notarize.zip" \
  --key "$TMPDIR_TK/auth_key.p8" \
  --key-id "$NOTARY_KEY_ID" \
  --issuer "$NOTARY_ISSUER_ID" \
  --wait

xcrun stapler staple "$BUNDLE"
echo "Notarized $BUNDLE"
