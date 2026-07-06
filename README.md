# Passkeys that turn into real keys.

<img src="macos/keytap.icon/Assets/icon.png" width="128" alt="keytap icon" />

`keytap` is a CLI that turns one passkey into unique keys you can reproduce anywhere.

If your passkey already syncs across your devices, `keytap` lets you use that passkey as a stable root secret.
From that root, it can deterministically derive:

- an `age` identity
- an SSH keypair
- a 32-byte app secret

It can also use the derived `age` identity directly to encrypt and decrypt files.

The mental model is simple:

> your passkey is the root secret, and `keytap` deterministically derives named child keys from it.

Same passkey + same name = same key.
Different name = different key.

<!--HELP:BEGIN-->
```
Derive keys and encrypt files from a passkey.

Usage: keytap <COMMAND> [ARGS]

Commands
  init                                                           Create the passkey (only needed once)
  public [NAME] [--as VAL]                                       Output the public key
  reveal [NAME] [--as VAL]                                       Reveal private key material
  encrypt [FILE] [--output VAL] [--key VAL] [--to VAL] [-R VAL]  Encrypt with the derived age identity (stdin/stdout by default)
  decrypt [FILE] [--output VAL] [--key VAL]                      Decrypt an age file with the derived age identity (stdin/stdout by default)

Arguments & options
  NAME          Key name for domain separation  [default: default]
  --as VAL      Output format  (hex | base64 | age | ssh)  [default: hex]
  FILE          Files to encrypt ('-' or omitted = stdin). Multiple files are each written to `<file>.age` (one authentication for the whole batch)
  --output VAL  Write ciphertext here ('-' = stdout). Only valid with a single input
  --key VAL     Key name for domain separation  [default: default]
  --to VAL      Additional age recipient (can be repeated)
  -R VAL        File containing age recipients (one per line)

Reusing a key without re-authenticating each time: see `keytap reveal --help`.
Run `keytap <COMMAND> --help` for the full details of any command.
```
<!--HELP:END-->


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

### Auth via phone over relay (fallback)

When keytap authenticates via your phone, additional trust considerations apply:

- **You trust the web page served to your phone.** The website served by `keytap.jul.sh` performs the WebAuthn ceremony, receives the PRF output, encrypts it, and posts back to the host, via the relay. You trust its functionality and integrity. The web page is served inspectable, but in practice you are unlikely to review it each time.
- The Cloudflare relay (`keytap-relay.julsh.workers.dev`) forwards opaque encrypted blobs. It never sees plaintext key material. The channel is end-to-end encrypted with X25519 ECDH + HKDF-SHA256 + AES-256-GCM. An attacker who controls the relay can deny service but cannot decrypt the payload.

## Sessions

`keytap` derives keys on demand and **never caches** them. That keeps the tool
simple and leaves nothing sensitive at rest — but it means each derivation costs
one passkey authentication. When you need to reuse a key without re-authenticating,
don't reach for a keytap daemon (there isn't one, by design): hand the derived key
to a **standard agent or keychain** and let *it* hold the key.

### SSH: pipe into `ssh-agent`

For many SSH connections, load the derived key into `ssh-agent` once. Every
`ssh` afterward is silent until the (optional) TTL expires:

```bash
eval "$(ssh-agent -s)"
keytap reveal ha --as ssh | ssh-add -t 900 -   # one auth, 15-minute hold
# ssh … ssh …  → no prompts
```

This is the intended path for repeated SSH — keytap produces the key, `ssh-agent`
holds it. There is deliberately no `keytap ssh` command; `ssh-agent` already does
that job, with better hardening.

### A secret reused within one script

Bind it to a shell variable for the process lifetime — one auth, no persistence:

```bash
KEY=$(keytap reveal deploy --as hex)
use "$KEY"; use "$KEY"
unset KEY
```

### A secret reused across shells: the OS keychain

For arbitrary secrets (API tokens, `age` keys) that outlive one process, the OS
keychain is the right holder — it enforces ACLs keytap can't. Write through
stdin (never argv, which is visible in the process list), under service
`keytap` with the key name as the account so entries stay recognizable:

```bash
# macOS (`security -i` reads the command from stdin)
security -i <<<"add-generic-password -U -s keytap -a deploy -w $(keytap reveal deploy --as age)"
security find-generic-password -s keytap -a deploy -w        # read back

# Linux (libsecret)
keytap reveal deploy --as age | secret-tool store --label=keytap service keytap key deploy
secret-tool lookup service keytap key deploy                 # read back
```

This trades keytap's zero-persistence for a larger footprint — an explicit,
auditable one, in a store designed to hold secrets.

Whatever you pipe into now holds the key, and must be trusted accordingly.

## Tips

### Streaming and batching

`encrypt`/`decrypt` read stdin and write stdout by default, so they compose in
pipelines with no plaintext temp files, at any size:

```bash
printf '%s' "$SECRET" | keytap encrypt --key backup > secret.age   # stdin → stdout
keytap decrypt secret.age --key backup -o >(load-into-env)          # → a consumer, no temp file
keytap encrypt *.env --key backup                                   # batch: one auth, each → <file>.age
```

### Use with the `age` CLI

`keytap` has built-in `encrypt` and `decrypt`, but you can also use derived keys with the regular `age` CLI:

```bash
echo "secret" | age -r "$(keytap public notes --as age)" > secret.age
age -d -i <(keytap reveal notes --as age) secret.age
```

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
