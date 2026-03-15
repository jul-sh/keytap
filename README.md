# prf-cli

A macOS command-line tool that derives SSH keys, `age` identities, and other secrets from passkeys using the WebAuthn PRF extension.

Same passkey, same `--name`, same derived key. Different names derive different keys. Works on any Mac where you can unlock the same passkey.

## Install

### From release

Download the latest release:

```bash
curl -fLO "$(curl -fsSL https://api.github.com/repos/jul-sh/tapkey/releases/latest | grep browser_download_url | cut -d '"' -f 4)"
unzip prf-cli-*.zip
mkdir -p ~/.local/share/prf-cli ~/.local/bin
rm -rf ~/.local/share/prf-cli/PrfCli.app
mv PrfCli.app ~/.local/share/prf-cli/
ln -sf ~/.local/share/prf-cli/PrfCli.app/Contents/MacOS/prf-cli ~/.local/bin/prf-cli
```

Release artifacts are signed, notarized, and can be verified against GitHub Actions build attestation:

```bash
gh attestation verify prf-cli-*.zip -R jul-sh/tapkey
```

### From source

Requires macOS 15+, Xcode Command Line Tools, and a [paid Apple Developer Program membership](https://developer.apple.com/programs/) for the Associated Domains entitlement. If you do not have one, use the release build instead.

```bash
git clone https://github.com/jul-sh/tapkey.git
cd tapkey
make install
```

## Usage

Register a passkey (only needed once, on the first Mac):

```bash
prf-cli register
```

Derive key material:

```bash
prf-cli derive
prf-cli derive --format base64
prf-cli derive --format raw
prf-cli derive --format age
prf-cli derive --format ssh
```

Use `--name` to derive different keys from the same passkey:

```bash
prf-cli derive --name backup
prf-cli derive --name deploy
prf-cli derive --name age --format age
prf-cli derive --name ssh --format ssh
```

The default name is `default`.

Get the public key for a derived key:

```bash
prf-cli public-key --name ssh --format ssh
```

### age

```bash
echo "secret" | age -r "$(prf-cli public-key --name age)" > secret.age
age -d -i <(prf-cli derive --name age --format age) secret.age
```

### SSH

```bash
prf-cli derive --name ssh --format ssh > ~/.ssh/id_prf
chmod 600 ~/.ssh/id_prf
prf-cli public-key --name ssh --format ssh
```

## How It Works

1. `prf-cli register` creates a passkey scoped to the WebAuthn relying party `tapkey.jul.sh`. The passkey lives in your chosen passkey provider (e.g. iCloud Keychain).
2. `prf-cli derive` performs a WebAuthn assertion with the PRF extension. The PRF input is `SHA256("tapkey:prf:<name>")`, so each `--name` produces a different PRF output directly from the passkey.
3. The PRF output is expanded with HKDF-SHA256 to produce 32 bytes of key material.
4. The result is formatted as raw bytes, hex, base64, an `age` secret key, or an OpenSSH Ed25519 key.

Replace the passkey root (rotates all derived keys):

```bash
prf-cli register --replace
```

### Relying party domain

The release build uses `tapkey.jul.sh` as the WebAuthn relying party. This domain hosts an [Associated Domains](https://developer.apple.com/documentation/bundleresources/entitlements/com_apple_developer_associated-domains) file (`.well-known/apple-app-site-association`) that tells macOS which app bundle is authorized to use passkeys for that origin.

The domain is only an identifier — when using prf-cli locally, all key derivation happens on your device and no secret material is sent to `tapkey.jul.sh`. If the domain were to become unavailable or its Associated Domains file were revoked, the release build would lose access to its passkeys (breaking functionality), but keys already derived would be unaffected.

However, because the PRF salts and HKDF parameters are deterministic and public, a hostile operator of the relying party domain could serve a web page that requests a WebAuthn PRF assertion with the same salts prf-cli uses. If you visited that page and approved the passkey prompt in your browser, the page's JavaScript would receive the PRF output and could derive the same keys. This requires active user interaction (you'd see a passkey authentication prompt), but there's no visual indication that approving it exposes your derived keys.

To eliminate this trust dependency, change `Config.relyingParty` in the source to a domain you control, host the Associated Domains file there, and build with your own Apple Developer account. This creates a separate set of passkeys.

## Security

The passkey is the root secret.

- Security depends on your passkey provider, WebAuthn PRF, and local device authentication. prf-cli does not create a stronger trust boundary than the provider already gives you.
- prf-cli does not sync or cache derived keys. It derives on demand, writes to stdout, and exits.
- If you save the output, pipe it into another tool, or import it into an agent, that destination now holds the key and must be trusted accordingly.
- The local config file stores only the credential ID used to select the passkey. It is not secret key material.
- The PRF inputs are public and derived from `--name`. They provide stable derivation and domain separation, not secrecy.
- Replacing the registered passkey changes every key derived from it.

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
