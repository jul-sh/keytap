# Passkeys that turn into real keys.

<img src="macos/keytap.icon/Assets/icon.png" width="128" alt="keytap icon" />

keytap is a smol CLI that lets you recover the same SSH key, `age` identity, or app secret on any machine where you can unlock the same passkey.

Passkey providers sync passkeys. They usually do not sync arbitrary private keys such as SSH keys. keytap bridges that gap by deriving the key locally after passkey authentication, without manually copying private key files between machines.

## Install

```bash
URL=$(curl -fsSL https://api.github.com/repos/jul-sh/keytap/releases/latest \
  | grep -o '"browser_download_url": *"[^"]*"' | cut -d '"' -f 4 \
  | grep "$([ "$(uname -s)" = Darwin ] && echo arm64 || echo linux)") \
  && curl -fLO "$URL" && mkdir -p ~/.local/bin \
  && if [ "$(uname -s)" = Darwin ]; then
       mkdir -p ~/.local/share/keytap && unzip -o keytap-*-arm64.zip -d ~/.local/share/keytap \
       && ln -sf ~/.local/share/keytap/Keytap.app/Contents/MacOS/keytap ~/.local/bin/keytap
     else
       unzip -o keytap-*-linux*.zip keytap -d ~/.local/bin
     fi
```

Releases are built in CI with [build attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations). To verify the binary was built from this repo's source (requires [GitHub CLI](https://cli.github.com/)):

```bash
gh attestation verify keytap-*.zip -R jul-sh/keytap
```

## Usage

Create the passkey once:

```bash
keytap init
```

Then derive a key.

```bash
keytap public myKey             # public key (safe to share)
keytap reveal myKey             # private key material (sensitive)
```

Use a name to derive different keys from the same passkey:

```bash
keytap public backup
keytap public deploy
keytap public                   # The default name is `default`.
```

Different formats:

```bash
keytap public myKey --format age
keytap public myKey --format ssh
keytap reveal myKey --format age
keytap reveal myKey --format ssh
keytap reveal myKey --format raw
```

### Encrypt and decrypt files

Encrypt a file with your derived age identity:

```bash
keytap encrypt secrets.env > secrets.env.age
```

Decrypt it:

```bash
keytap decrypt secrets.env.age > secrets.env
```

Encrypt to yourself and others:

```bash
keytap encrypt secrets.env --to age1abc... > secrets.env.age
```

Or use a recipients file (one age public key per line):

```bash
keytap encrypt secrets.env -R age-recipients.txt > secrets.env.age
```

Encrypt to others only, without including yourself:

```bash
keytap encrypt secrets.env --to age1abc... --no-self > secrets.env.age
```

Use a different key name:

```bash
keytap encrypt secrets.env --key backup > secrets.env.age
keytap decrypt secrets.env.age --key backup > secrets.env
```

## Requirements

### macOS (native passkey)
- macOS 15.0 or later
- Apple Silicon (`arm64`)
- A passkey provider with PRF support (like Apple's built-in Password Manager)

### Linux / other platforms (auth via phone)
- A phone with a passkey provider that supports the PRF extension

## How It Works

1. `keytap init` creates a passkey for the relying party `keytap.jul.sh`. The passkey lives in your chosen passkey provider.
2. `keytap public|reveal [name]` performs a WebAuthn assertion using the PRF extension. The PRF input is `SHA256("keytap:prf:<name>")`, so each name requests a different PRF output directly from the passkey.
3. The PRF output is expanded with HKDF-SHA256 using a fixed keytap info string to produce 32 bytes of key material.
4. `public` outputs the public key (hex, base64, age recipient, or SSH public key). `reveal` outputs private key material. `encrypt`/`decrypt` use the derived age identity to encrypt or decrypt files directly.

Same passkey, same name, same derived key. Different names derive different keys.

### Platforms

On macOS passkey support is native, authentication is as simple as touching Touch ID.

On systems without native passkey support (like Linux), keytap authenticates via your phone over an encrypted relay. It prints a QR code to stderr, you scan it on your phone, approve with your passkey, and the result is sent back over an end-to-end encrypted channel (X25519 + AES-256-GCM). The relay never sees plaintext key material.

## Security

keytap is a convenience utility, not a high-assurance security tool. It is designed to make passkey-derived keys easy to use across machines. If your threat model involves nation-state adversaries, targeted attacks, or secrets where compromise has severe consequences, use purpose-built tools instead:

- **SSH keys**: Generate directly with `ssh-keygen` and manage per-device keys. Use [FIDO2 resident keys](https://developers.yubico.com/SSH/Securing_git_with_SSH_and_FIDO2.html) on a hardware token for phishing-resistant SSH without syncing private material at all.
- **age encryption**: Generate standalone identities with `age-keygen`. See [age](https://github.com/FiloSottile/age) and [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey) for hardware-bound identities.

keytap ties all derived keys to a single passkey registered under the `keytap.jul.sh` relying party. That means you trust your passkey provider, the WebAuthn PRF extension, and the `keytap.jul.sh` domain. This is a meaningful trust surface that the tools above avoid entirely.

With that said, here is how keytap works within those constraints:

- keytap does not sync or cache derived keys. It derives on demand, writes to stdout, and exits. There are no local config files or cached state.
- If you save the output, pipe it into another tool, or import it into an agent, that destination now holds the key and must be trusted accordingly.
- The PRF inputs are public and derived from the key name. They provide stable derivation and domain separation, not secrecy.
- Replacing the registered passkey changes every key derived from it. Treat the passkey as the root of your derived identities.

### Auth via phone over relay (non-macOS)

When keytap authenticates via your phone, additional trust considerations apply:

- **You trust the web page served to your phone.** The website served by `keytap.jul.sh` performs the WebAuthn ceremony, receives the PRF output, encrypts it, and posts back to the host, via the relay. You trust its functionality and integrity. The web page is served inspectable, but in practice you are unlikely to review it each time.
- The Cloudflare relay (`keytap-relay.julsh.workers.dev`) forwards opaque encrypted blobs. It never sees plaintext key material. The channel is end-to-end encrypted with X25519 ECDH + HKDF-SHA256 + AES-256-GCM. An attacker who controls the relay can deny service but cannot decrypt the payload.

## Tips

### Nix flake

Add keytap to a Nix shell using the attested, signed release:

```nix
{
  inputs.keytap.url = "github:jul-sh/keytap";

  outputs = { keytap, ... }: {
    # add keytap.packages.${system}.default to your buildInputs
  };
}
```

### Storing a derived key in macOS Keychain

If you want to avoid re-authenticating every time, you can store a derived key in the macOS Keychain:

```bash
security add-generic-password -s keytap -a AGE_SECRET_KEY -w "$(keytap reveal myKey --format age)"
```

### Usage with age CLI

keytap has built-in encryption via `encrypt` and `decrypt`, but you can also use the `age` CLI directly with derived keys:

```bash
echo "secret" | age -r "$(keytap public smolSecrets --format age)" > secret.age
age -d -i <(keytap reveal smolSecrets --format age) secret.age
```

## License

MIT
