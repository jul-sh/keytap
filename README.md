# tapkey

<img src="tapkey.icon/Assets/ChatGPT Image Mar 15, 2026 at 10_01_47 PM-2.png" width="128" alt="tapkey icon" />

tapkey is a tiny macOS CLI that lets you recover the same SSH key, `age` identity, or app secret on any Mac where you can unlock the same passkey.

Passkey providers sync passkeys. They usually do not sync arbitrary private keys such as SSH keys. tapkey bridges that gap by deriving the key locally after passkey authentication, without manually copying private key files between machines.

For example, iCloud Keychain syncs passkeys tied to your Apple account, but it will not sync an SSH private key. tapkey lets that synced passkey act as the root, so the SSH key can be re-derived locally on each of your Macs.

If the passkey you need is on your iPhone and not on the Mac in front of you, that is still fine. macOS will show a QR code, you scan it, approve with Apple's native passkey flow, and the Mac gets just the secret material needed to derive the same key locally. No tapkey sync service, no private-key file shuffling, no extra account.

## Install

### From release

Download the latest release:

```bash
curl -fLO "$(curl -fsSL https://api.github.com/repos/jul-sh/tapkey/releases/latest | grep browser_download_url | cut -d '"' -f 4)"
unzip tapkey-*.zip
mkdir -p ~/.local/share/tapkey ~/.local/bin
rm -rf ~/.local/share/tapkey/Tapkey.app
mv Tapkey.app ~/.local/share/tapkey/
ln -sf ~/.local/share/tapkey/Tapkey.app/Contents/MacOS/tapkey ~/.local/bin/tapkey
```

Release artifacts are signed, notarized, and can be verified against GitHub Actions build attestation, so you can check that the release binary was built securely from the public, auditable source code in this repository:

```bash
gh attestation verify tapkey-*.zip -R jul-sh/tapkey
```

The verification step requires the [GitHub CLI](https://cli.github.com/). It is optional but recommended.

### From source

Requires macOS 15+, Xcode Command Line Tools, and a [paid Apple Developer Program membership](https://developer.apple.com/programs/) for the Associated Domains entitlement. If you do not have one, use the release build instead; releases are already signed and notarized with my Apple Developer account.

```bash
git clone https://github.com/jul-sh/tapkey.git
cd tapkey
make install
```

## Usage

Create the passkey once, only needed on the first Mac:

```bash
tapkey register
```

Then derive key material:

```bash
tapkey derive [name]
```

Use a name to derive different keys from the same passkey:

```bash
tapkey derive backup
tapkey derive deploy
```

Derive key material in different formats:

```bash
tapkey derive myBase64Key --format base64
tapkey derive myRawKey --format raw
tapkey derive smolSecrets --format age
tapkey derive smolSshKey --format ssh
```

The default name is `default`.

Get the public key for a derived key, e.g. a key named `smolSshKey`:

```bash
tapkey public-key smolSshKey --format ssh
```

### age

E.g. using an age key called `smolSecrets`

```bash
echo "secret" | age -r "$(tapkey public-key smolSecrets)" > secret.age
age -d -i <(tapkey derive smolSecrets --format age) secret.age
```

### SSH

```bash
tapkey derive ssh --format ssh > ~/.ssh/id_tapkey
chmod 600 ~/.ssh/id_tapkey
tapkey public-key ssh --format ssh
```

## How It Works

1. `tapkey register` creates a passkey for the relying party `tapkey.jul.sh`. The passkey lives in your chosen passkey provider.
2. `tapkey derive` performs a WebAuthn assertion using the PRF extension. The PRF input is `SHA256("tapkey:prf:<name>")`, so each name requests a different PRF output directly from the passkey.
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
- The PRF inputs are public and derived from the key name. They provide stable derivation and domain separation, not secrecy.
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
