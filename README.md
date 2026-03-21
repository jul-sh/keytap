# Passkeys that turn into real keys.

<img src="macos/keytap.icon/Assets/icon.png" width="128" alt="keytap icon" />

`keytap` is a CLI that turns one passkey into reproducible keys.

If your passkey already syncs across your devices, `keytap` lets you use that passkey as a stable root secret you can unlock anywhere.
From that root, it can deterministically derive:

- an `age` identity
- an SSH keypair
- a 32-byte app secret

It can also use the derived `age` identity directly to encrypt and decrypt files.

The mental model is simple:

> your passkey is the root secret, and `keytap` deterministically derives named child keys from it.

Same passkey + same name = same key.
Different name = different key.


## Why this exists

Passkey providers are good at syncing passkeys.
They are not designed to sync arbitrary private keys like your SSH key for GitHub, your `age` identity for encrypted files, or an app secret used by a script or service.

So people fall back to awkward alternatives: manually copying plaintext private keys between machines, storing long-lived secrets in more places than they want, or generating different keys per device and dealing with the sprawl.


## How it works

At a high level, `keytap` does four things:

1. You register a passkey for the relying party `keytap.jul.sh`.
2. When you ask for a key name like `default`, `backup`, or `deploy`, `keytap` runs a WebAuthn authentication ceremony using the PRF extension.
3. The passkey returns deterministic PRF output for that name.
4. `keytap` turns that output into 32 bytes of key material and formats it as SSH, `age`, hex, base64, or raw bytes.

The name is just domain separation.
It lets one passkey produce many independent keys.

Examples:

- `default` for your main identity
- `github` for GitHub SSH auth
- `backup` for encrypted backups

The important property is predictability, across installs:

- same passkey, same name → same derived key
- same passkey, different name → different derived key
- different passkey → completely different keys

## Platform model

### macOS

On macOS, `keytap` uses the native passkey flow.
In the normal case, that means the CLI triggers a local WebAuthn ceremony and you approve it with Touch ID or your system passkey UI.

### Linux and other non-native environments

On platforms where the CLI cannot do the passkey ceremony natively, `keytap` falls back to a nearby-phone flow.

The flow is:

1. the CLI prints a QR code
2. you scan it with your phone
3. your phone opens the `keytap` page
4. you approve with a passkey on the phone
5. the PRF result is sent back to the CLI over an end-to-end encrypted relay channel

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

Releases are built in CI with [build attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations).
To verify a downloaded release was built from this repository:

```bash
gh attestation verify keytap-*.zip -R jul-sh/keytap
```

## Quick start

### 1. Create the passkey once

```bash
keytap init
```

This creates the passkey that `keytap` will use as the root for future derivations.

### 2. Derive a key

```bash
keytap public
keytap reveal
```

By default, both commands use the name `default`.

To derive a different key, pass a different name:

```bash
keytap public github
keytap public backup
keytap reveal deploy
```

### 3. Choose an output format

Public key formats:

```bash
keytap public github --format ssh
keytap public backup --format age
keytap public default --format hex
keytap public default --format base64
```

Private key formats:

```bash
keytap reveal github --format ssh
keytap reveal backup --format age
keytap reveal default --format hex
keytap reveal default --format base64
keytap reveal default --format raw
```

### 4. Encrypt a file

```bash
keytap encrypt .env > .env.age
```

This derives the same `age` identity from your passkey and uses it immediately for encryption.

### 5. Decrypt it later

```bash
keytap decrypt .env.age > .env
```

The same passkey and key name reproduce the same identity, so the file can be decrypted on any machine where you can unlock that passkey.

## Common workflows

### Derive an SSH key

Get an SSH public key you can paste into GitHub, GitLab, or a server:

```bash
keytap public github --format ssh
```

Reveal the corresponding SSH private key when a tool needs it:

```bash
keytap reveal github --format ssh
```

Think of `github` here as a stable namespace.
You can make another independent SSH key by choosing another name.

### Derive an `age` identity

Get your `age` recipient:

```bash
keytap public files --format age
```

Reveal the matching secret key:

```bash
keytap reveal files --format age
```

### Encrypt and decrypt files

Encrypt a file with your derived age identity:

```bash
keytap encrypt secrets.env > secrets.env.age
```

Decrypt it later:

```bash
keytap decrypt secrets.env.age > secrets.env
```

Use a different key name when you want an independent encryption domain:

```bash
keytap encrypt secrets.env --key work > secrets.env.age
keytap decrypt secrets.env.age --key work > secrets.env
```

Encrypt to yourself and someone else at the same time:

```bash
keytap encrypt secrets.env --to age1abc... > secrets.env.age
```

Or use a recipients file:

```bash
keytap encrypt secrets.env -R age-recipients.txt > secrets.env.age
```

Encrypt to others only, without including yourself:

```bash
keytap encrypt secrets.env --to age1abc... --no-self > secrets.env.age
```

## Choosing names

Names are cheap, so use them liberally.
A good rule is: one name per purpose.

For example:

- `github`
- `gitlab`
- `backup`
- `terraform`
- `notes`

This is cleaner than reusing one key everywhere, and easier to reason about than a pile of manually managed key files.

## Requirements

### macOS

- macOS 15.0 or later
- Apple Silicon (`arm64`)
- a passkey provider with PRF support, such as Apple's built-in Passwords integration

### Linux / other platforms

- a phone with a passkey provider that supports the PRF extension

## Security model

`keytap` is best understood as a convenience tool with a clean deterministic model, not as a maximal-security key management system.

If your threat model requires hardware-bound keys, strict per-device isolation, or minimizing trust in synced credentials, then traditional tools are often the better choice:

- use `ssh-keygen` or FIDO2-backed SSH keys for SSH
- use `age-keygen` or hardware-backed `age` setups for encryption

What `keytap` optimizes for is different:

- one synced passkey
- reproducible derived keys
- minimal setup on a new machine
- no private key file transfer step

Within that model:

- `keytap` derives keys on demand and does not maintain a local key database
- if you save or pipe revealed private material somewhere, that destination becomes part of your trust boundary
- replacing the underlying passkey changes every derived key
- the key name is not secret; it is used for stable separation between derived keys

### Extra trust assumptions in phone mode

When using the QR-code / phone flow, there are additional trust assumptions:

- you trust the web page served at `keytap.jul.sh` to perform the WebAuthn ceremony correctly
- you trust the nearby flow implementation to encrypt the response before it reaches the relay
- the relay forwards encrypted blobs; it can block or drop traffic, but it is not supposed to learn plaintext key material

So the nearby mode is practical and useful, but it is not equivalent to a purely local hardware-backed flow.

## Tips

### Use with the `age` CLI

`keytap` has built-in `encrypt` and `decrypt`, but you can also use derived keys with the regular `age` CLI:

```bash
echo "secret" | age -r "$(keytap public notes --format age)" > secret.age
age -d -i <(keytap reveal notes --format age) secret.age
```

### Store a derived key in macOS Keychain

If you want fewer auth prompts, you can store a derived secret in Keychain yourself:

```bash
security add-generic-password -s keytap -a AGE_SECRET_KEY -w "$(keytap reveal myKey --format age)"
```

This trades convenience for a larger persistence footprint.

### Nix flake

```nix
{
  inputs.keytap.url = "github:jul-sh/keytap";

  outputs = { keytap, ... }: {
    # add keytap.packages.${system}.default to your buildInputs
  };
}
```

## In one sentence

`keytap` is for people who want their passkey to behave like a portable root of identity, from which they can deterministically regenerate the keys their tools actually need.

## License

MIT
