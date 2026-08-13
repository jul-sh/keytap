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

On macOS, Keytap uses native passkey support.

For nearby approval, Keytap displays a QR code that opens a website on your
phone. Use your passkey there, and the result is sent back to the machine over
an end-to-end encrypted channel.

## Security

Keytap is a convenience utility, not a high-assurance security tool. It is
designed to make passkey-derived keys easy to use across machines. If your
threat model involves nation-state adversaries, targeted attacks, or secrets
where compromise has severe consequences, use purpose-built tools instead.

With that said, here is how Keytap works within those constraints:

- Keytap does not sync or cache derived keys. It derives on demand, writes the
  requested output to stdout, and exits.
- The local credential record contains a credential ID and, after nearby
  pairing, a public identity pin—not derived private key material.
- If you save the output, pipe it into another tool, or import it into an agent,
  that destination now holds the key and must be trusted accordingly.
- Losing or replacing the passkey can make every previously derived key
  unrecoverable. Keep an independent recovery path.

### Authentication via phone over relay via QR code

When you scan Keytap's QR code and authenticate with your passkey on your
phone, additional trust considerations apply:

- **You trust the web page served to your phone.** The page served by
  `keytap.jul.sh` performs the WebAuthn ceremony, receives the PRF output,
  encrypts the result, and returns it to the CLI through the relay. Its source
  is inspectable, but in practice you are unlikely to review it before every
  approval.
- **You do not need to trust the relay with plaintext key material.** The
  Cloudflare relay at `keytap-relay.julsh.workers.dev` forwards opaque
  encrypted messages. The channel uses P-256 ECDH, HKDF-SHA-256, and
  AES-256-GCM end to end. A relay operator can observe connection metadata,
  delay or drop messages, or deny service, but cannot decrypt or silently alter
  an accepted result.
- The first nearby pairing relies on matching the same two words on both
  devices. It then pins the passkey's public identity; later approvals require
  a fresh signature over the one-use request.
