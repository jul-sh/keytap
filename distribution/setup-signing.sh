#!/bin/bash
# Sets up Developer ID signing certificate and provisioning profile.
#
# Usage:
#   ./distribution/setup-signing.sh           # Create keychain & import cert
#   ./distribution/setup-signing.sh --cleanup  # Remove temporary keychain
#
# Requires AGE_SECRET_KEY environment variable (or reads from macOS Keychain via get-age-key.sh).

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
KEYCHAIN_NAME="prf_cli_signing.keychain-db"
KEYCHAIN_PATH="$HOME/Library/Keychains/$KEYCHAIN_NAME"

if [ "$1" = "--cleanup" ]; then
    security delete-keychain "$KEYCHAIN_PATH" 2>/dev/null || true
    exit 0
fi

# Decrypt provisioning profile if not already present
decrypt_profile() {
    if [ -f "$PROJECT_ROOT/PrfCli.provisionprofile" ]; then
        return
    fi
    local age_key
    age_key=$("$SCRIPT_DIR/get-age-key.sh") || return 1
    printf '%s' "$age_key" > /tmp/_tk_age.txt
    age -d -i /tmp/_tk_age.txt "$PROJECT_ROOT/secrets/PROVISION_PROFILE_BASE64.age" \
        | base64 --decode > "$PROJECT_ROOT/PrfCli.provisionprofile"
    rm -f /tmp/_tk_age.txt
    echo "Decrypted provisioning profile"
}

# Check if Developer ID signing identity is already usable
if security find-identity -v -p codesigning 2>/dev/null | grep -q "Developer ID Application"; then
    decrypt_profile || true
    echo "Developer ID certificate already available"
    exit 0
fi

# Resolve AGE_SECRET_KEY
AGE_SECRET_KEY=$("$SCRIPT_DIR/get-age-key.sh") || exit 1

# Use a hash of the AGE key as the keychain password (keychains have length limits)
KEYCHAIN_PASSWORD=$(printf '%s' "$AGE_SECRET_KEY" | shasum -a 256 | cut -d' ' -f1)

# If keychain exists, try to unlock it with the derived password
if [ -f "$KEYCHAIN_PATH" ]; then
    if security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH" 2>/dev/null; then
        # Re-add to search list in case it was dropped
        EXISTING=$(security list-keychains -d user | tr -d '" ' | tr '\n' ' ')
        security list-keychains -d user -s "$KEYCHAIN_PATH" $EXISTING
        decrypt_profile || true
        echo "Signing keychain unlocked: $KEYCHAIN_NAME"
        exit 0
    fi
    # Password didn't work, remove stale keychain
    security delete-keychain "$KEYCHAIN_PATH" 2>/dev/null || true
fi

# Decrypt secrets
printf '%s' "$AGE_SECRET_KEY" > /tmp/_tk_age.txt
P12_PASS=$(age -d -i /tmp/_tk_age.txt "$PROJECT_ROOT/secrets/MACOS_P12_PASSWORD.age")
age -d -i /tmp/_tk_age.txt "$PROJECT_ROOT/secrets/MACOS_P12_BASE64.age" \
    | base64 --decode > /tmp/_tk_dev.p12
rm -f /tmp/_tk_age.txt

# Create temporary keychain with derived password
security delete-keychain "$KEYCHAIN_PATH" 2>/dev/null || true
security create-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"
security set-keychain-settings -t 3600 "$KEYCHAIN_PATH"
security unlock-keychain -p "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH"

# Import certificate
security import /tmp/_tk_dev.p12 -k "$KEYCHAIN_PATH" -P "$P12_PASS" \
    -T /usr/bin/codesign
rm -f /tmp/_tk_dev.p12

# Install Apple intermediate certificate for trust chain
curl -sL "https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer" \
    -o /tmp/_tk_intermediate.cer
security add-certificates -k "$KEYCHAIN_PATH" /tmp/_tk_intermediate.cer 2>/dev/null || true
rm -f /tmp/_tk_intermediate.cer

# Allow codesign to access keys without prompt
security set-key-partition-list \
    -S apple-tool:,apple:,codesign: \
    -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH" >/dev/null

# Add to keychain search list
EXISTING=$(security list-keychains -d user | tr -d '" ' | tr '\n' ' ')
security list-keychains -d user -s "$KEYCHAIN_PATH" $EXISTING

decrypt_profile || true

echo "Signing keychain ready: $KEYCHAIN_NAME"
