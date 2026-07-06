# Passkeys that turn into real keys.

<img src="macos/keytap.icon/Assets/icon.png" width="128" alt="keytap icon" />

`keytap` is a CLI that turns one passkey into unique keys you can reproduce anywhere.

If your passkey already syncs across your devices, `keytap` lets you use that passkey as a stable root secret.
From that root, it can deterministically derive:

- an `age` identity
- an SSH keypair
- a 32-byte app secret

It can also use the derived `age` identity directly to encrypt and decrypt data (stdin to stdout; point the shell at files).

The mental model is simple:

> your passkey is the root secret, and `keytap` deterministically derives named child keys from it.

Same passkey + same name = same key.
Different name = different key.

<!--HELP:BEGIN-->
```
Derive keys and encrypt files from a passkey.

Usage: keytap <COMMAND> [ARGS]

Commands
  init                                Create the passkey (only needed once)
  public [NAME] [--as VAL]            Output the public key
  reveal [NAME] [--as VAL]            Reveal private key material
  encrypt [NAME] [--to VAL] [-R VAL]  Encrypt stdin to stdout with the derived age identity
  decrypt [NAME]                      Decrypt age input from stdin to stdout with the derived age identity
  remember NAME                       Remember a derived key on this machine (no more prompts for it)
  forget [NAME] [--all]               Forget a remembered key
  remembered                          List keys remembered on this machine (never prints key material)

Arguments & options
  NAME      Key name for domain separation  [default: default]
  --as VAL  Output format  (hex | base64 | age | ssh)  [default: hex]
  --to VAL  Additional age recipient (can be repeated)
  -R VAL    File containing age recipients (one per line)
  --all     Forget every remembered key, including ones from previous passkeys

Skip repeated prompts for a key: `keytap remember NAME` (see `keytap remember --help`).
Holds that expire instead (ssh-agent, TTLs): see `keytap reveal --help`.
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

By default nothing is stored; run the same command on another machine and you
get the same key there. If a prompt per use is too much friction,
`keytap remember NAME` keeps that derived key on that machine
(see [Skipping repeated prompts](#skipping-repeated-prompts)).

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

- By default keytap does not sync or cache derived keys. It derives on demand, writes to stdout, and exits. There are no local config files, and no state is stored implicitly.
- The one explicit exception is `keytap remember NAME`: it stores that derived key on this machine, with no TTL, until `keytap forget`, `keytap forget --all`, or passkey replacement. The key lands in a plain file (not encrypted at rest), silently upgraded to the OS keychain when the machine has one (then encrypted at rest by it). Either way, any process running as your user may be able to invoke keytap and use the key without a ceremony.
- Remembered keys are tied to a fingerprint of the registered passkey credential. `keytap init` is a root boundary: it wipes all remembered entries, and lookups are scoped to the current root, so keys remembered under a replaced passkey are never used.
- If you save the output, pipe it into another tool, or import it into an agent, that destination now holds the key and must be trusted accordingly.
- The PRF inputs are public and derived from the key name. They provide stable derivation and domain separation, not secrecy.
- Replacing the registered passkey changes every key derived from it. Treat the passkey as the root of your derived identities.

### Auth via phone over relay (fallback)

When keytap authenticates via your phone, additional trust considerations apply:

- **You trust the web page served to your phone.** The website served by `keytap.jul.sh` performs the WebAuthn ceremony, receives the PRF output, encrypts it, and posts back to the host, via the relay. You trust its functionality and integrity. The web page is served inspectable, but in practice you are unlikely to review it each time.
- The Cloudflare relay (`keytap-relay.julsh.workers.dev`) forwards opaque encrypted blobs. It never sees plaintext key material. The channel is end-to-end encrypted with X25519 ECDH + HKDF-SHA256 + AES-256-GCM. An attacker who controls the relay can deny service but cannot decrypt the payload.

## Skipping repeated prompts

By default every command derives on demand; each use costs one passkey prompt.
When that is too much friction, pick a holder for the key.

### Remember the key on this machine

`keytap remember` runs one ceremony, then stores the derived raw key on that
machine. Later keytap commands for that name stop prompting. There is no TTL;
the key stays until you forget it or replace the passkey.

```bash
keytap remember deploy      # one ceremony; 'deploy' stops prompting on this machine
keytap reveal deploy        # instant, no prompt
keytap remembered           # list remembered names (never key material)
keytap forget deploy        # back to prompting; or: keytap forget --all
```

Remembered keys are bound to the passkey that produced them. `keytap init`
replaces the root and wipes every remembered entry; keys remembered under an
old passkey are never used. Remembering is per machine.

Where the key lives: a plain file, `~/.local/state/keytap/remembered.json`
(0600, honors `$XDG_STATE_HOME`). On machines with an OS keychain (macOS
Keychain; Secret Service on desktop Linux), `remember` upgrades to it
automatically; entries are then auditable under service `keytap`, account
`remember:<root>:<name>`, encrypted at rest by the keychain. The success
message says which of the two was used, and lookups check the keychain first.

Be clear-eyed about the plain file (what you get on headless Linux, servers,
and containers, where Secret Service needs a desktop session): it is not
encrypted at rest, so anyone who can read your files (root, backups, disk
images) can use the key. Treat it like an unencrypted SSH private key.

The trade-off: any process running as your user may be able to invoke keytap
and use a remembered key without a ceremony. If you want a hold that expires
instead, use an agent:

### SSH via `ssh-agent`

Load the derived key into `ssh-agent` once; every `ssh` afterward is silent
until the TTL runs out:

```bash
eval "$(ssh-agent -s)"
keytap reveal ha --as ssh | ssh-add -t 900 -   # one auth, 15-minute hold
```

There is deliberately no `keytap ssh` command; `ssh-agent` already does that
job, with better hardening.

### A secret reused within one script

Bind it to a shell variable for the process lifetime:

```bash
KEY=$(keytap reveal deploy --as hex)
use "$KEY"; use "$KEY"
unset KEY
```

### Other tools that read secrets from the OS keychain

You can write revealed keys into the keychain yourself
(`security add-generic-password`, `secret-tool store`); keytap never touches
entries it didn't create. Usually simpler: remember the key and have the other
tool run `keytap reveal`, which no longer prompts.

Whatever holds the key must be trusted accordingly.

## Tips

### Streaming

`encrypt`/`decrypt` are pure filters: stdin in, stdout out, streamed at any
size. Files are the shell's job, so pipelines never need plaintext temp files:

```bash
printf '%s' "$SECRET" | keytap encrypt backup > secret.age   # stdin → stdout
keytap decrypt backup < secret.age | load-into-env           # → a consumer, no temp file
```

(Older keytaps had a multi-file batch mode to amortize one ceremony across
many files; `keytap remember` made that redundant, so v6 removed it.)

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
