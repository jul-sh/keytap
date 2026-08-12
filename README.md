# Keytap

<img src="macos/keytap.icon/Assets/icon.png" width="128" alt="keytap icon" />

Keytap is a CLI for deriving reproducible SSH keys and `age` identities
anywhere you can unlock your passkey.

Unlock with Touch ID; or approve using a passkey on a nearby device.

> **Pre-release:** Expect breaking changes. Do not make Keytap the only way to
> recover important secrets.

[Try the web demo](https://keytap.jul.sh).

<!--HELP:BEGIN-->
```
Derive keys and encrypt files from a passkey.

Usage: keytap <COMMAND> [ARGS]

Commands
  init [--nearby]                                Create a keytap passkey, if you do not already have one
  public [NAME] [--as VAL] [--nearby]            Output the public key
  reveal [NAME] [--as VAL] [--nearby]            Reveal private key material
  encrypt [NAME] [--to VAL] [-R VAL] [--nearby]  Encrypt stdin to stdout with the derived age identity
  decrypt [NAME] [--nearby]                      Decrypt age input from stdin to stdout with the derived age identity
  remember NAME [--nearby]                       Remember a derived key on this machine (no more prompts for it)
  forget [NAME] [--all]                          Forget a remembered key
  remembered                                     List keys remembered on this machine (never prints key material)

Arguments & options
  --nearby  Run the passkey ceremony on a nearby device only
  NAME      Key name for domain separation  [default: default]
  --as VAL  Output format  (hex | base64 | age | ssh)  [default: hex]
  --to VAL  Additional age recipient (can be repeated)
  -R VAL    File containing age recipients (one per line)

Options
  --prompt  Allow passkey ceremonies under $CI (only affects commands that need one)

Skip repeated prompts for a key: `keytap remember NAME` (see `keytap remember --help`).
Holds that expire instead (ssh-agent, TTLs): see `keytap reveal --help`.
CI (headless, $CI set): keys come from `$KEYTAP_KEY_<NAME>` — see `keytap reveal --help`.
Run `keytap <COMMAND> --help` for the full details of any command.
```
<!--HELP:END-->

## Install

```bash
case "$(uname -s)/$(uname -m)" in
  Darwin/arm64) ASSET='arm64.zip' ;;
  Linux/x86_64) ASSET='linux-x86_64.zip' ;;
  *) echo 'Keytap has no release for this platform.' >&2; exit 1 ;;
esac
URL=$(curl -fsSL 'https://api.github.com/repos/jul-sh/keytap/releases?per_page=1' \
  | grep -o '"browser_download_url": *"[^"]*"' | cut -d '"' -f 4 \
  | grep "$ASSET$") \
  && curl -fLO "$URL" && mkdir -p ~/.local/bin \
  && if [ "$(uname -s)" = Darwin ]; then
       mkdir -p ~/.local/share/keytap && unzip -o keytap-*-arm64.zip -d ~/.local/share/keytap \
       && rm -f ~/.local/bin/keytap \
       && if [ -x ~/.local/share/keytap/Keytap.app/Contents/Resources/keytap-launcher ]; then
            install -m 755 ~/.local/share/keytap/Keytap.app/Contents/Resources/keytap-launcher \
              ~/.local/bin/keytap \
            && KEYTAP_LAUNCHER_REGISTER_ONLY=1 ~/.local/bin/keytap
          else
            printf '%s\n' '#!/bin/sh' \
              'exec "$HOME/.local/share/keytap/Keytap.app/Contents/MacOS/keytap" "$@"' \
              > ~/.local/bin/keytap \
            && chmod 755 ~/.local/bin/keytap \
            && /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister \
              -f ~/.local/share/keytap/Keytap.app \
            && sleep 2
          fi
     else
       unzip -o keytap-*-linux-x86_64.zip keytap -d ~/.local/bin
     fi
```

Releases are built in CI with [build attestation](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations).
To verify a downloaded release was built from this repository:

```bash
gh attestation verify keytap-*.zip -R jul-sh/keytap
```

## Approval

When a command needs a passkey ceremony on macOS, Keytap opens the native
prompt and shows a QR code plus a forwardable approval URL; the first verified
approval wins.
Registration uses one route: `keytap init` is native, while
`keytap init --nearby` uses a nearby device. Other platforms use nearby
approval.

Nearby approval sends one outbound secure WebSocket from each device to a
short-lived relay. The URL fragment carries a fresh P-256 public key whose
private half stays in the CLI. The endpoints use P-256 key agreement and
HKDF-SHA-256 to derive directional AES-256-GCM keys; the relay forwards only
public handshake data and sequenced ciphertext. It sees connection timing and
message sizes, but cannot read an approval or alter one without detection.

The first nearby pairing uses a commit-reveal exchange to show the same two
words on the approval page and in the terminal. Both sides must confirm them
before the browser opens a WebAuthn prompt. That ceremony atomically pins the
exact credential and an Ed25519 identity derived from the passkey PRF. A
locally created passkey performs this pairing on its first nearby use. Later
approvals need no word comparison: each uses a fresh, one-use encrypted
invitation and must match the pinned passkey identity. Every key result is
signed over the exact request, returned key material, credential, and
one-time-versus-remember choice.

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
- The relay is not trusted for secrecy or integrity. It can observe public
  handshake data, timing, and message sizes, and it can delay, drop, or close a
  room. Endpoint authentication and encryption prevent it from reading or
  silently changing an accepted request or result.
- Treat the QR code as a trusted invitation from the CLI you intend to approve.
  Each invitation is fresh, encrypted, and usable once. Confirm the two words
  on both displays during the first nearby pairing; that pairing pins the
  passkey identity, and later approvals authenticate it without another word
  comparison.
- The approval page necessarily handles the PRF result and passkey-derived
  identity material before encrypting them to the CLI. Trust the code served
  by `keytap.jul.sh` and the browser running it.

## Guides

- [Share an encrypted `.env` through Git with multiple developers](docs/team-env.md)
- [Deploy the Cloudflare approval relay](docs/relay.md)

## License

MIT
