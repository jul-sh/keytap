# Keytap

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

## Security

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
