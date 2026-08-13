# Keytap

Keytap derives reproducible key material from a WebAuthn PRF-capable passkey.
Its complete command surface is: create the passkey, print a named public key,
or reveal the matching private key.

> **Pre-release:** Expect breaking changes. Do not make Keytap the only way to
> recover important keys.

## Commands

```text
Derive reproducible keys from a passkey.

Usage: keytap <COMMAND> [ARGS]

Commands
  init                                       Create a keytap passkey, if you do not already have one
  public [NAME] [--as <hex|base64|age|ssh>]  Output the public key
  reveal [NAME] [--as <hex|base64|age|ssh>]  Reveal private key material

Arguments & options
  NAME  Key name for domain separation  [default: default]
  --as  Output format  [default: hex]

Run `keytap <COMMAND> --help` for command details.
```

`keytap init` creates the passkey and a local credential record. It refuses to
replace an existing record; `keytap init --force` replaces it, which changes
every derived key.

`public` and `reveal` each require a fresh passkey assertion. Keytap derives the
named key for that invocation and does not persist the derived key.

Names must be non-empty ASCII strings of at most 128 characters. A name is
domain separation, so one passkey can reproducibly produce independent keys:

```sh
keytap init
keytap public
keytap public deploy --as ssh
keytap reveal backup --as age
```

## Formats

Both output commands accept the same four format names:

| `--as` | `public` | `reveal` |
| --- | --- | --- |
| `hex` | lowercase hex X25519 public key | lowercase hex 32-byte secret |
| `base64` | standard Base64 X25519 public key | standard Base64 32-byte secret |
| `age` | `age1...` X25519 recipient | `AGE-SECRET-KEY-...` identity |
| `ssh` | OpenSSH Ed25519 public key | OpenSSH Ed25519 private key |

The SSH public-key comment is `keytap:<name>`. All output is newline-terminated;
the SSH private key uses LF line endings.

## Approval

On macOS 15 or later, `init` uses the native passkey registration UI. It falls
back to nearby registration only when macOS reports a safe fallback; an
indeterminate native result stops instead of risking a second credential.

For `public` and `reveal`, macOS starts native AuthenticationServices and nearby
approval together. The first fully verified result wins and the other route is
cancelled.

On Linux, registration and assertions use nearby approval. The CLI prints a QR
code and a one-use URL for a current browser and PRF-capable passkey device.

The browser `/nearby` page and its relay are support infrastructure for those
CLI invitations. They are not a standalone key tool or demo.

The first nearby pairing displays the same two words in the terminal and
browser. After both sides confirm them, Keytap pins the credential ID and a
passkey-derived Ed25519 public identity locally. A passkey created through the
native macOS flow performs this pairing on its first nearby use. Later nearby
results must carry a fresh signature from that pinned identity.

## Build from source

Rust is required everywhere. The macOS app additionally requires macOS 15 or
later, Python 3, and the Xcode/Swift toolchain. Browser and relay tests require
Node.js/npm; building the deployable nearby page additionally requires
`wasm-pack`.

Build, sign, and install the local macOS app bundle and launcher with:

```sh
make install
```

This installs `Keytap.app` under `~/.local/share/keytap` and the `keytap`
launcher under `~/.local/bin`. The Makefile uses ad-hoc signing by default. It
automatically embeds `Keytap.provisionprofile` when that file exists; set
`IDENTITY` and `PROVISIONING_PROFILE=/path/to/profile` to override those
defaults. A profile is optional for a nearby-only build, while native passkeys
require signing that authorizes the associated-domain entitlement. If native
approval is unavailable, `public` and `reveal` can still finish through nearby
approval; `init` falls back only when macOS reports that doing so is safe.

On Linux, build and install the nearby-only binary directly:

```sh
cargo build --release -p keytap --locked
mkdir -p "$HOME/.local/bin"
install -m 755 target/release/keytap "$HOME/.local/bin/keytap"
```

Build the nearby page's minimal identity WASM and stage its static deployment
with `make build-web`. Run the available local suite with `make test`; on macOS
it also runs the Swift bridge and launcher tests. Portable Rust and browser
tests can be run separately:

```sh
cargo test -p keytap-core -p keytap -p keytap-web --locked
npm --prefix web test
```

## Security model

Keytap is a convenience tool, not a high-assurance key manager.

The passkey PRF output is expanded with HKDF-SHA-256 into a 32-byte named
secret. The CLI holds the PRF output and raw key in zeroizing buffers, then
writes the requested representation to stdout. Its local credential record
contains the credential ID and, after nearby pairing, a public identity
pin—not a named private key.

Nearby invitations carry a fresh P-256 public key in the URL fragment; its
private half remains in the CLI. P-256 key agreement and HKDF-SHA-256 produce
directional AES-256-GCM channel keys. The relay sees public handshake data,
timing, and message sizes, and can delay, drop, or close a room. It cannot read
or silently alter an accepted request or result.

Key names are domain separators, not secrets. Anyone who receives `reveal`
output receives that private key and must be trusted. Losing or replacing the
passkey can make every previous key unrecoverable, so keep an independent
recovery path.

Nearby approval trusts the browser, the code served at `keytap.jul.sh`, the
passkey provider, WebAuthn PRF, and the first two-word comparison. Treat every
QR code and URL as an invitation from the exact CLI process you intend to
approve.

## License

MIT
