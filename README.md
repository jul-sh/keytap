# tapkey

<img src="macos/tapkey.icon/Assets/icon.png" width="128" alt="tapkey icon" />

tapkey is a smol CLI that lets you recover the same SSH key, `age` identity, or app secret on any machine where you can unlock the same passkey.

Passkey providers sync passkeys. They usually do not sync arbitrary private keys such as SSH keys. tapkey bridges that gap by deriving the key locally after passkey authentication, without manually copying private key files between machines.

For example, iCloud Keychain syncs passkeys tied to your Apple account, but it will not sync an SSH private key. tapkey lets that synced passkey act as the root, so the SSH key can be re-derived locally on each of your Macs. If the passkey is on your iPhone and not on the Mac in front of you, macOS will natively show a QR code for cross-device authentication.

On systems without native passkey support (like Linux), tapkey shows a QR code you scan on your phone. The phone performs the passkey ceremony and relays the result back over an end-to-end encrypted channel (X25519 + AES-256-GCM). The relay never sees plaintext key material.

## Install

```bash
curl -fLO "$(curl -fsSL https://api.github.com/repos/jul-sh/tapkey/releases/latest | grep browser_download_url | cut -d '"' -f 4)"
mkdir -p ~/.local/bin && unzip -o tapkey-*.zip -d ~/.local/bin
```

Releases are built in CI with [build attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations). To verify the binary was built from this repo's source (requires [GitHub CLI](https://cli.github.com/)):

```bash
gh attestation verify tapkey-*.zip -R jul-sh/tapkey
```

## Requirements

### macOS (native passkey)
- macOS 15.0 or later
- Apple Silicon (`arm64`)
- A passkey provider with PRF support (like Apple's built-in Password Manager)

### Linux / other platforms (QR relay)
- A phone with a passkey provider that supports the PRF extension

## Usage

Create the passkey once:

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
tapkey derive # The default name is `default`.
```

Derive key material in different formats:

```bash
tapkey derive myBase64Key --format base64
tapkey derive myRawKey --format raw
tapkey derive smolSecrets --format age
tapkey derive smolSshKey --format ssh
```

Get the public key for a derived key, e.g. a key named `smolSshKey`:

```bash
tapkey public-key smolSshKey --format ssh
```

## How It Works

1. `tapkey register` creates a passkey for the relying party `tapkey.jul.sh`. The passkey lives in your chosen passkey provider.
2. `tapkey derive` performs a WebAuthn assertion using the PRF extension. The PRF input is `SHA256("tapkey:prf:<name>")`, so each name requests a different PRF output directly from the passkey.
3. The PRF output is expanded with HKDF-SHA256 using a fixed tapkey info string to produce 32 bytes of key material.
4. The result is formatted as raw bytes, hex, base64, an `age` secret key, or an OpenSSH Ed25519 key.

Same passkey, same name, same derived key. Different names derive different keys.

If you ever intentionally want to replace the tapkey passkey root, just run `tapkey register` again.

## Security

tapkey's security model is simple: the passkey is the root secret.

- tapkey depends on your passkey provider, WebAuthn PRF, and local device authentication. It does not create a stronger trust boundary than the provider already gives you.
- tapkey does not sync or cache derived keys itself. It derives on demand, writes to stdout, and exits. There are no local config files or cached state.
- If you save the output, pipe it into another tool, or import it into an agent, that destination now holds the key and must be trusted accordingly.
- The PRF inputs are public and derived from the key name. They provide stable derivation and domain separation, not secrecy.
- Replacing the registered passkey changes every key derived from it. Treat the passkey as the root of your derived identities.

### QR relay mode (non-macOS)

When tapkey uses the QR relay flow, additional trust considerations apply:

- **You trust the web page served to your phone.** The website served by `tapkey.jul.sh` performs the WebAuthn ceremony, receives the PRF output, encrypts it, and posts back to the host, via the relay. You trust its functionality and integrity. The web page is served inspectable, but in practice you are unlikely to review it each time.
- The Cloudflare relay (`tapkey-relay.julsh.workers.dev`) forwards opaque encrypted blobs. It never sees plaintext key material. The channel is end-to-end encrypted with X25519 ECDH + HKDF-SHA256 + AES-256-GCM. An attacker who controls the relay can deny service but cannot decrypt the payload.
- On macOS hosts, none of this applies. The native passkey flow uses the hosts passkeys, or alternatively a native QR code with that opens a native direct device-to-device channel.

In other words: tapkey is not a vault. It is a deterministic derivation tool built on top of passkey security.

## Tips

### Storing a derived key in macOS Keychain

If you want to avoid re-authenticating every time, you can store a derived key in the macOS Keychain:

```bash
security add-generic-password -s tapkey -a AGE_SECRET_KEY -w "$(tapkey derive myKey --format age)"
```

### Usage with age

E.g. using an age key called `smolSecrets`

```bash
echo "secret" | age -r "$(tapkey public-key smolSecrets)" > secret.age
age -d -i <(tapkey derive smolSecrets --format age) secret.age
```

## License

MIT
