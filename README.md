# tapkey

Derive deterministic symmetric keys from a passkey via the WebAuthn PRF extension.

Same passkey on any device — same key. Works with any passkey provider that supports PRF (iCloud Keychain, 1Password, etc.). No server, no secrets to copy between machines.

## Install

### From release (recommended)

Download the latest release:

```bash
gh release download --repo jul-sh/tapkey --pattern 'tapkey-*.zip'
unzip tapkey-*.zip
# Symlink into PATH
mkdir -p ~/.local/bin
ln -sf "$(pwd)/Tapkey.app/Contents/MacOS/tapkey" ~/.local/bin/tapkey
```

#### Verify build attestation

Compute the artifact digest and verify it against Sigstore's transparency log:

```bash
sha256sum tapkey-*.zip
gh attestation download tapkey-*.zip -R jul-sh/tapkey
cosign verify-blob-attestation \
  --bundle <sha256:HASH>.jsonl \
  --new-bundle-format \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  --certificate-identity-regexp="^https://github.com/jul-sh/tapkey/.github/workflows/release.yml" \
  tapkey-*.zip
```

This verifies that the binary was built by the expected GitHub Actions workflow, the signature is valid in Sigstore's transparency log (Rekor), and the artifact digest matches.

### From source

Requires macOS 15+, Xcode Command Line Tools, and a [paid Apple Developer Program membership](https://developer.apple.com/programs/) (Associated Domains entitlement requires it).

```bash
git clone https://github.com/jul-sh/tapkey.git
cd tapkey
make install
```

This compiles, codesigns with entitlements, and symlinks to `~/.local/bin/tapkey`.

## Usage

### First-time setup

Create a passkey (one-time — macOS will let you choose your passkey provider):

```bash
tapkey register
```

### Derive a key

```bash
tapkey derive                              # 32-byte key as hex (default)
tapkey derive --format base64              # base64
tapkey derive --format raw                 # raw bytes to stdout
tapkey derive --format age                 # AGE-SECRET-KEY-1...
tapkey derive --format ssh                 # OpenSSH Ed25519 private key
```

### Named keys

Use `--name` to derive different keys from the same passkey. Each name deterministically produces a different key:

```bash
tapkey derive --name backup                # one key for backups
tapkey derive --name deploy                # a different key for deploys
tapkey derive --name age --format age      # age encryption key
tapkey derive --name ssh --format ssh      # SSH key
```

The default name is `"default"`.

### Public keys

```bash
tapkey public-key                          # age public key (age1...)
tapkey public-key --name ssh --format ssh  # ssh-ed25519 AAAA...
```

### Use with age

```bash
# Encrypt
echo "secret" | age -r $(tapkey public-key --name age) > secret.age

# Decrypt
age -d -i <(tapkey derive --name age --format age) secret.age
```

### Use with SSH

```bash
# Write SSH key
tapkey derive --name ssh --format ssh > ~/.ssh/id_tapkey
chmod 600 ~/.ssh/id_tapkey

# Get public key for authorized_keys / GitHub
tapkey public-key --name ssh --format ssh
```

## How it works

1. **Register** creates a passkey via `ASAuthorizationPlatformPublicKeyCredentialProvider` with the relying party `tapkey.jul.sh`. The passkey is stored in your chosen passkey provider (iCloud Keychain, 1Password, etc.) and syncs across devices.

2. **Derive** performs a WebAuthn assertion with the [PRF extension](https://w3c.github.io/webauthn/#prf-extension) (macOS 15+). The PRF extension takes a fixed salt and returns a deterministic 32-byte `SymmetricKey` bound to the passkey credential.

3. The PRF output is passed through **HKDF-SHA256** with info string `"tapkey:<name>"` to derive 32 bytes of key material. Different `--name` values produce different keys from the same PRF output.

4. The derived bytes are formatted as hex, base64, an age secret key (Bech32), an OpenSSH Ed25519 key, or raw bytes.

## Security model

### What's trusted

- **Your passkey provider** (iCloud Keychain, 1Password, etc.) — passkeys are synced via the provider's E2E encryption. For iCloud Keychain, the credential secret never leaves the Secure Enclave, and access is gated by biometric authentication.
- **The PRF extension** — deterministic output bound to the specific credential; different credentials produce different outputs even with the same salt.
- **HKDF-SHA256** — standard key derivation with domain separation via the `--name` parameter.
- **GitHub Actions build attestation** (if using a release binary) — Sigstore-signed SLSA provenance proves the binary was built by the expected workflow from this repository. Verify via cosign + Rekor (see [install](#verify-build-attestation)).

### What's public and safe to expose

- **PRF salt** (`SHA256("tapkey:prf-salt-v1")`) — fixed, deterministic, public. Knowing the salt doesn't help without the passkey.
- **Credential ID** (stored in `~/Library/Containers/sh.jul.tapkey/Data/.config/tapkey/credential.json`) — identifies which passkey to use, not secret. It's equivalent to a username.
- **HKDF info strings** (`"tapkey:<name>"`) — public domain-separation labels.

### Domain separation

The `--name` flag sets the HKDF info string to `"tapkey:<name>"`. HKDF info is part of the expand step in the extract-then-expand construction, so different names produce cryptographically independent keys. The info string is used as raw bytes — there is no parsing, escaping, or normalization, so the mapping from name to key is injective. However, names that are prefixes of each other (e.g. `"a"` vs `"ab"`) are still fully independent because HKDF processes the entire info string as an opaque input to HMAC.

### Threat model

- **Attacker with physical access to unlocked Mac**: Can derive keys if they can authenticate with the passkey provider. tapkey is a convenience tool for key derivation, not a vault — it provides the same protection as your passkey provider's authentication (biometrics, device PIN, etc.).
- **Attacker with stolen provider credentials**: Would also need a trusted device to approve passkey sync. Your provider's recovery protections apply.
- **Attacker who compromises the binary**: Build attestation via Sigstore provides supply chain verification. Verify the artifact digest against the Rekor transparency log before trusting a release binary.

### What tapkey does NOT do

- Store or transmit derived keys — they're printed to stdout and forgotten
- Cache PRF output or derived keys
- Phone home or make network requests
- Run persistently — it launches, prompts for passkey authentication, outputs the key, and exits

## Requirements

- macOS 15.0 (Sequoia) or later
- Apple Silicon (arm64)
- A passkey provider with PRF support (iCloud Keychain, 1Password, etc.)
- Paid Apple Developer Program membership (for building from source — Associated Domains entitlement requires it)

## Development

```bash
# Enter dev shell (provides age, gh)
nix develop

# Build and sign
make

# Build, sign, and install
make install

# Verify codesigning
make verify

# Clean
make clean
```

### Encrypting secrets for CI

```bash
# Encrypt a secret
echo -n "secret-value" | age -R secrets/age-recipients.txt -o secrets/SECRET_NAME.age

# Decrypt (locally)
AGE_SECRET_KEY=$(./distribution/get-age-key.sh)
echo "$AGE_SECRET_KEY" | age -d -i - secrets/SECRET_NAME.age
```

## License

MIT
