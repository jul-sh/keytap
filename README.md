# tapkey

tapkey is a tiny macOS app that lets you recover the same SSH key, `age` identity, or app secret on any Mac where you can unlock the same passkey.

Passkey providers sync passkeys. They usually do not sync arbitrary private keys such as SSH keys. tapkey bridges that gap by deriving the key locally after passkey authentication, without manually copying private key files between machines.

For example, iCloud Keychain syncs passkeys tied to your Apple account, but it will not sync an SSH private key. tapkey lets that synced passkey act as the root, so the SSH key can be re-derived locally on each of your Macs.

Under the hood, tapkey uses the WebAuthn PRF extension to derive a deterministic 32-byte secret from a passkey, then expands it with HKDF-SHA256. There is no tapkey key-sync service. For nearby-device use, tapkey can open a small web view on `tapkey.jul.sh` so you can authenticate with a passkey on a nearby iPhone and still derive locally on the Mac you are using.

## Install

### From release

Download the latest release:

```bash
gh release download --repo jul-sh/tapkey --pattern 'tapkey-*.zip'
unzip tapkey-*.zip
mkdir -p ~/.local/bin
ln -sf "$(pwd)/Tapkey.app/Contents/MacOS/tapkey" ~/.local/bin/tapkey
```

Release artifacts are signed, notarized, and can be verified against GitHub Actions build attestation, so you can check that the release binary was built securely from the public, auditable source code in this repository:

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

### From source

Requires macOS 15+, Xcode Command Line Tools, and a [paid Apple Developer Program membership](https://developer.apple.com/programs/) for the Associated Domains entitlement. If you do not have one, use the release build instead; releases are already signed and notarized with my Apple Developer account.

```bash
git clone https://github.com/jul-sh/tapkey.git
cd tapkey
make install
```

## Usage

Create the passkey once, on the first Mac:

```bash
tapkey register
```

Most of the time you can just run:

```bash
tapkey derive
```

tapkey first tries a local or synced passkey. If none is available, it falls back to nearby-device passkey flow so you can approve the request on your iPhone.

Derive key material in different formats:

```bash
tapkey derive
tapkey derive --format base64
tapkey derive --format raw
tapkey derive --format age
tapkey derive --format ssh
```

Use `--name` to derive different keys from the same passkey:

```bash
tapkey derive --name backup
tapkey derive --name deploy
tapkey derive --name age --format age
tapkey derive --name ssh --format ssh
```

The default name is `default`.

Get the public key for a derived key:

```bash
tapkey public-key
tapkey public-key --name ssh --format ssh
```

### age

```bash
echo "secret" | age -r "$(tapkey public-key --name age)" > secret.age
age -d -i <(tapkey derive --name age --format age) secret.age
```

### SSH

```bash
tapkey derive --name ssh --format ssh > ~/.ssh/id_tapkey
chmod 600 ~/.ssh/id_tapkey
tapkey public-key --name ssh --format ssh
```

## How It Works

1. `tapkey register` creates a passkey for the relying party `tapkey.jul.sh`. The passkey lives in your chosen passkey provider.
2. `tapkey derive` performs a WebAuthn assertion using the PRF extension. The PRF input is `SHA256("tapkey:prf:<name>")`, so each `--name` requests a different PRF output directly from the passkey.
3. The PRF output is expanded with HKDF-SHA256 using a fixed tapkey info string to produce 32 bytes of key material.
4. The result is formatted as raw bytes, hex, base64, an `age` secret key, or an OpenSSH Ed25519 key.

Same passkey, same name, same derived key. Different names derive different keys.

If you ever intentionally want to replace the tapkey passkey root, use:

```bash
tapkey register --replace
```

## Security

tapkey's security model is simple: the passkey is the root secret.

- tapkey depends on your passkey provider, WebAuthn PRF, and local device authentication. It does not create a stronger trust boundary than the provider already gives you.
- tapkey does not sync or cache derived keys itself. It derives on demand, writes to stdout, and exits.
- If you save the output, pipe it into another tool, or import it into an agent, that destination now holds the key and must be trusted accordingly.
- The local config file stores only the credential ID used to select the passkey. It is not secret key material.
- The PRF inputs are public and derived from `--name`. They provide stable derivation and domain separation, not secrecy.
- Nearby-device flow loads `https://tapkey.jul.sh/nearby.html` in a sandboxed `WKWebView`. That page is part of the trusted computing base for nearby derivation, and the app needs network access for that flow.
- Replacing the registered passkey changes every key derived from it. Treat the passkey as the root of your derived identities.

In other words: tapkey is not a vault. It is a deterministic derivation tool built on top of passkey security.

## Requirements

- macOS 15.0 or later
- Apple Silicon (`arm64`)
- A passkey provider with PRF support (like Apple's built-in Password Manager)

## Development

```bash
# Enter dev shell
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

### Encrypting Secrets For CI

```bash
echo -n "secret-value" | age -R secrets/age-recipients.txt -o secrets/SECRET_NAME.age

AGE_SECRET_KEY=$(./distribution/get-age-key.sh)
echo "$AGE_SECRET_KEY" | age -d -i - secrets/SECRET_NAME.age
```

## License

MIT
