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
  forget [NAME]                                                  End a key's session (the next use prompts again)

Arguments & options
  NAME          Key name for domain separation  [default: default]
  --as VAL      Output format  (hex | base64 | age | ssh)  [default: hex]
  FILE          Files to encrypt ('-' or omitted = stdin). Multiple files are each written to `<file>.age` (one authentication for the whole batch)
  --output VAL  Write ciphertext here ('-' = stdout). Only valid with a single input
  --key VAL     Key name for domain separation  [default: default]
  --to VAL      Additional age recipient (can be repeated)
  -R VAL        File containing age recipients (one per line)

Sessions: a key's first use holds it in your OS keychain for 12h (like sudo),
so repeat uses don't re-prompt. Details and controls: `keytap reveal --help`.
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

- keytap does not sync derived keys and has no config files or state of its own. By default it holds each derived key in your OS keychain for a 12-hour [session](#sessions) so repeat use doesn't re-prompt; `KEYTAP_SESSION=off` restores zero persistence, and `keytap forget NAME` ends a session early.
- If you save the output, pipe it into another tool, or import it into an agent, that destination now holds the key and must be trusted accordingly.
- The PRF inputs are public and derived from the key name. They provide stable derivation and domain separation, not secrecy.
- Replacing the registered passkey changes every key derived from it. Treat the passkey as the root of your derived identities.

### Auth via phone over relay (fallback)

When keytap authenticates via your phone, additional trust considerations apply:

- **You trust the web page served to your phone.** The website served by `keytap.jul.sh` performs the WebAuthn ceremony, receives the PRF output, encrypts it, and posts back to the host, via the relay. You trust its functionality and integrity. The web page is served inspectable, but in practice you are unlikely to review it each time.
- The Cloudflare relay (`keytap-relay.julsh.workers.dev`) forwards opaque encrypted blobs. It never sees plaintext key material. The channel is end-to-end encrypted with X25519 ECDH + HKDF-SHA256 + AES-256-GCM. An attacker who controls the relay can deny service but cannot decrypt the payload.

## Sessions

The first use of a key name runs the passkey ceremony, then holds the derived
key in your **OS keychain** for 12 hours — like `sudo` remembering your
password. Repeat uses of that name, across commands and shells, are silent
until the session expires or you end it:

```bash
keytap reveal deploy                # passkey prompt; 12h session starts
keytap reveal deploy                # silent
keytap encrypt *.env --key deploy   # still silent
keytap forget deploy                # session over; next use prompts again
```

A session hit is byte-identical to a fresh derivation — keys are deterministic,
so holding one can never change what you get, only whether you're prompted.

Control the window with `KEYTAP_SESSION`:

```bash
export KEYTAP_SESSION=30m                 # shorter sessions
KEYTAP_SESSION=off keytap reveal deploy   # hold nothing (a prompt per derivation)
```

**The trade, stated plainly:** while a session is live, any process running as
your user can read that key by invoking keytap — the same trade `sudo` makes
during its grace period. The held key lives in your OS keychain (service
`keytap`, account = key name), encrypted at rest and visible in Keychain
Access / seahorse; other apps reading the entry directly still hit the
keychain's own ACL prompt. If that trade is wrong for a key, run
`keytap forget NAME` right after use, or set `KEYTAP_SESSION=off`.

On Linux, sessions need `secret-tool` (package `libsecret-tools`) and a running
secret service; without one, keytap silently falls back to a ceremony per
derivation.

### SSH: pipe into `ssh-agent`

For SSH connections, `ssh-agent` is still the better holder — it was built for
exactly this job, with its own timeout and hardening:

```bash
eval "$(ssh-agent -s)"
keytap reveal ha --as ssh | ssh-add -t 900 -   # one auth, 15-minute hold
# ssh … ssh …  → no prompts
```

There is deliberately no `keytap ssh` command; `ssh-agent` already does that
job better.

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
