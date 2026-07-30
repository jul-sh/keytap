# Deploy the approval relay

The Worker in `web/relay` gives each nearby approval a short-lived Durable
Object room. It accepts one CLI and one approver, forwards bounded binary
frames, and retains a temporary tombstone after either peer leaves. A managed
per-source rate limit rejects abusive upgrades before allocating a room.
Encryption and authentication happen only at the endpoints; the Worker has no
key or provider secrets. Each one-use invitation creates one room and
establishes an endpoint-encrypted channel. The QR code is a trusted handoff
from the CLI; the first nearby pairing confirms two matching words and
atomically pins the passkey credential and passkey-derived identity. Later
approvals bind the encrypted invitation to that pin without another
comparison.

Set the Cloudflare account in `web/relay/wrangler.jsonc`, then deploy:

```bash
cd web/relay
npx --yes wrangler@4.115.0 deploy
```

If the deployment uses another hostname, set that origin in the CLI and
approval page and allow its WebSocket URL in the page's Content Security
Policy. The `Deploy Relay Worker` workflow performs the same deployment for
this repository.
