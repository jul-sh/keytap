#!/bin/bash
# Notarize and staple a macOS app bundle.
# Usage: ./distribution/notarize.sh Keytap.app
set -euo pipefail

BUNDLE="${1:?Usage: notarize.sh <bundle>}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

TMPDIR_TK=$(mktemp -d)
trap 'rm -rf "$TMPDIR_TK"' EXIT

NOTARY_KEY_ID=$("$SCRIPT_DIR/read-secret.sh" NOTARY_KEY_ID)
NOTARY_ISSUER_ID=$("$SCRIPT_DIR/read-secret.sh" NOTARY_ISSUER_ID)
"$SCRIPT_DIR/read-secret.sh" NOTARY_KEY_BASE64 \
  | base64 --decode > "$TMPDIR_TK/auth_key.p8"

ditto -c -k --keepParent "$BUNDLE" "$TMPDIR_TK/notarize.zip"

xcrun notarytool submit "$TMPDIR_TK/notarize.zip" \
  --key "$TMPDIR_TK/auth_key.p8" \
  --key-id "$NOTARY_KEY_ID" \
  --issuer "$NOTARY_ISSUER_ID" \
  --wait --output-format json | tee "$TMPDIR_TK/result.json"

STATUS=$(python3 -c "import json,sys; print(json.load(sys.stdin)['status'])" < "$TMPDIR_TK/result.json")
if [ "$STATUS" != "Accepted" ]; then
  echo "error: notarization failed with status: $STATUS" >&2
  SUBMISSION_ID=$(python3 -c "import json,sys; print(json.load(sys.stdin)['id'])" < "$TMPDIR_TK/result.json")
  xcrun notarytool log "$SUBMISSION_ID" \
    --key "$TMPDIR_TK/auth_key.p8" \
    --key-id "$NOTARY_KEY_ID" \
    --issuer "$NOTARY_ISSUER_ID" || true
  exit 1
fi

# Staple with retries (propagation can lag)
for i in $(seq 1 10); do
  if xcrun stapler staple "$BUNDLE"; then
    break
  fi
  echo "Staple attempt $i failed, retrying in 15s..."
  sleep 15
  if [ "$i" -eq 10 ]; then
    echo "error: stapling failed after 10 attempts" >&2
    exit 1
  fi
done

echo "Notarized $BUNDLE"
