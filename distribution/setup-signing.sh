#!/bin/bash
# Sets up Developer ID signing certificate in a temporary keychain.
#
# Usage:
#   ./distribution/setup-signing.sh           # Create keychain & import cert
#   ./distribution/setup-signing.sh --cleanup  # Remove temporary keychain
#
# Reads encrypted cert secrets from secrets/*.age via keytap.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
KEYCHAIN_NAME="keytap_signing.keychain-db"
KEYCHAIN_PATH="$HOME/Library/Keychains/$KEYCHAIN_NAME"

source "$SCRIPT_DIR/signing-common.sh"

if [ "${1:-}" = "--cleanup" ]; then
    delete_temp_keychain "$KEYCHAIN_PATH"
    exit 0
fi

# Decrypt provisioning profile if not already present
decrypt_profile() {
    if [ -f "$PROJECT_ROOT/Keytap.provisionprofile" ]; then
        return
    fi
    "$SCRIPT_DIR/read-secret.sh" PROVISION_PROFILE_BASE64 \
        | base64 --decode > "$PROJECT_ROOT/Keytap.provisionprofile"
    echo "Decrypted provisioning profile"
}

# Repo-managed temp keychains are disposable. Never try to unlock a stale one.
delete_temp_keychain "$KEYCHAIN_PATH"

if all_codesigning_identities_available "Developer ID Application"; then
    decrypt_profile
    echo "Developer ID certificate already available"
    exit 0
fi

KEYCHAIN_PASSWORD=$(openssl rand -hex 16)
P12_PATH=$(mktemp "${TMPDIR:-/tmp}/keytap-dev-cert.XXXXXX.p12")

cleanup() {
    rm -f "$P12_PATH"
}

trap cleanup EXIT

P12_PASS=$("$SCRIPT_DIR/read-secret.sh" MACOS_P12_PASSWORD)
"$SCRIPT_DIR/read-secret.sh" MACOS_P12_BASE64 | base64 --decode > "$P12_PATH"

create_unlocked_temp_keychain "$KEYCHAIN_PATH" "$KEYCHAIN_PASSWORD"

# Import certificate
security import "$P12_PATH" -k "$KEYCHAIN_PATH" -P "$P12_PASS" \
    -T /usr/bin/codesign

# Install Apple intermediate certificate for trust chain
if ! security find-certificate -c "Developer ID Certification Authority" /Library/Keychains/System.keychain >/dev/null 2>&1; then
    INTERMEDIATE=$(mktemp "${TMPDIR:-/tmp}/keytap-intermediate.XXXXXX.cer")
    curl -sLo "$INTERMEDIATE" https://www.apple.com/certificateauthority/DeveloperIDG2CA.cer
    sudo security add-trusted-cert -d -r unspecified -k /Library/Keychains/System.keychain "$INTERMEDIATE"
    rm -f "$INTERMEDIATE"
fi

# Allow codesign to access keys without prompt
security set-key-partition-list \
    -S apple-tool:,apple:,codesign: \
    -s -k "$KEYCHAIN_PASSWORD" "$KEYCHAIN_PATH" >/dev/null

prepend_keychain_to_search_list "$KEYCHAIN_PATH"

decrypt_profile

echo "Signing keychain ready: $KEYCHAIN_NAME"
