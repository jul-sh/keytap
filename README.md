# Keytap

<img src="macos/keytap.icon/Assets/icon.png" width="128" alt="keytap icon" />

Keytap derives reproducible `age` identities, SSH keys, and 32-byte secrets
from a passkey using WebAuthn PRF. The same passkey and name produce the same
key wherever that passkey is available; different names produce independent
keys. Derived keys are not stored unless you choose `remember`.

> **Pre-release:** Expect breaking changes. Do not make Keytap the only way to
> recover important secrets.

[Try the web demo](https://keytap.jul.sh). It supports key derivation; nearby
approval, remembered keys, and CI behavior require the installed CLI.

## Install

Download the matching archive from the
[latest release](https://github.com/jul-sh/keytap/releases/latest). Releases
support Apple silicon macOS and x86-64 Linux. On macOS, keep `Keytap.app`
intact and put its `Contents/MacOS/keytap` executable on your `PATH`; on Linux,
put the `keytap` binary on your `PATH`.

With Nix:

```bash
nix profile install github:jul-sh/keytap
```

To verify a downloaded archive:

```bash
gh attestation verify keytap-*.zip -R jul-sh/keytap
```

## Quick start

```bash
keytap init                                # only if you do not already have a keytap passkey
keytap public github --as ssh
keytap encrypt backup < secret > secret.age
keytap decrypt backup < secret.age
```

Run `keytap <command> --help` for command-specific options.

<details>
<summary>Command reference</summary>

<!--HELP:BEGIN-->
```
Derive keys and encrypt files from a passkey.

Usage: keytap <COMMAND> [ARGS]

Commands
  init [--nearby]                     Create a keytap passkey, if you do not already have one
  public [NAME] [--as VAL]            Output the public key
  reveal [NAME] [--as VAL]            Reveal private key material
  encrypt [NAME] [--to VAL] [-R VAL]  Encrypt stdin to stdout with the derived age identity
  decrypt [NAME]                      Decrypt age input from stdin to stdout with the derived age identity
  remember NAME                       Remember a derived key on this machine (no more prompts for it)
  forget [NAME] [--all]               Forget a remembered key
  remembered                          List keys remembered on this machine (never prints key material)

Arguments & options
  --nearby  Register the passkey on a nearby device instead of this machine
  NAME      Key name for domain separation  [default: default]
  --as VAL  Output format  (hex | base64 | age | ssh)  [default: hex]
  --to VAL  Additional age recipient (can be repeated)
  -R VAL    File containing age recipients (one per line)
  --all     Forget every remembered key, including ones from previous passkeys

Options
  --prompt  Allow passkey ceremonies under $CI (only affects commands that need one)

Skip repeated prompts for a key: `keytap remember NAME` (see `keytap remember --help`).
Holds that expire instead (ssh-agent, TTLs): see `keytap reveal --help`.
CI (headless, $CI set): keys come from `$KEYTAP_KEY_<NAME>` — see `keytap reveal --help`.
Run `keytap <COMMAND> --help` for the full details of any command.
```
<!--HELP:END-->

</details>

## Approval

On macOS, commands using an existing passkey open the native prompt and print a
forwardable approval URL at the same time; the first verified approval wins.
Registration uses one route: `keytap init` is native, while
`keytap init --nearby` uses a nearby device. Other platforms use nearby
approval.

Nearby approval uses end-to-end encrypted WebRTC and tries direct P2P first. If
direct connection fails, only an allowlisted passkey identity may use the
managed relay; other identities receive a clear relay-access error.

`init --nearby` has its own terminal word check. Each CLI machine's first
nearby key request also requires comparing two words; later approval URLs for
that machine can be forwarded and approved remotely. macOS may still ask for
Local Network access. A stable signed release avoids repeated debug-build
firewall identities, but does not remove that privacy prompt.

## Remembered keys and CI

`keytap remember NAME` stores that derived key on the current machine without a
TTL, until `forget` or passkey replacement. It uses macOS Keychain or Linux
Secret Service when available; the fallback is an owner-only, unencrypted state
file. Treat remembered keys like private keys. **Use once** skips storing the
named key, but nearby pairing metadata is still retained.

By default, Keytap does not open an interactive ceremony when `$CI` is set. Set
`KEYTAP_KEY_<NAME>` to `keytap reveal <name> --as age` output; names are
uppercased and non-alphanumeric characters become `_`.

```bash
keytap reveal ci --as age | gh secret set KEYTAP_KEY_CI
```

Leaking that value permanently compromises the named key; retire the name.

## Security

Keytap is a convenience tool, not a high-assurance key manager. You trust your
passkey provider, WebAuthn PRF, and the `keytap.jul.sh` relying party.

- Losing the passkey can make every derived key unrecoverable; replacing it
  creates a different set of keys. Keep another recovery path.
- Anything receiving private output receives the key and must be trusted.
- Key names provide domain separation, not secrecy.
- Protect forwarded approval URLs from substitution. Anyone with the URL can
  observe request metadata, race approval, or deny service; the URL alone
  cannot forge the waiting CLI or authorize relay access. The approval page
  sees PRF-derived and nearby identity material.

## Guides

- [Share an encrypted `.env` through Git with multiple developers](docs/team-env.md)
- [Deploy Cloudflare signaling and allowlisted TURN](docs/turn.md)

## License

MIT
