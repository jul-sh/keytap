# Deploy Cloudflare signaling and TURN

The Signal Worker provides public signaling for every nearby connection.
Direct P2P and signaling are not allowlisted; the passkey allowlist is consulted
only after direct ICE fails and the clients request TURN credentials.

## Configure Cloudflare

Create a Realtime TURN key, then install its **TURN Token ID** and **API Token**
as Worker secrets. Never commit or send the API token to a client. See the
[TURN credential guide](https://developers.cloudflare.com/realtime/turn/generate-credentials/).

```bash
cd web/signal
npx --yes wrangler@4.115.0 secret put TURN_KEY_ID
npx --yes wrangler@4.115.0 secret put TURN_KEY_API_TOKEN
npx --yes wrangler@4.115.0 deploy
```

Authenticate Wrangler with `CLOUDFLARE_API_TOKEN`; the Cloudflare account ID is
in `wrangler.toml`.

## Manage the TURN allowlist

TURN access is tied to the stable Ed25519 identity that the nearby flow derives
from the passkey's PRF output. `TURN_PASSKEY_ALLOWLIST` in
`web/signal/src/index.js` contains the exact public identities permitted to use
TURN:

```javascript
const TURN_PASSKEY_ALLOWLIST = [
  {
    credentialId: "YMrfg78V4cqfr7NqwX_PkFZa13Y",
    publicKey: "Fl1qDq-BqriovSqe40CPvq3rz6ltvoSoQM6gSuJfIsA",
  },
];
```

Each entry has exactly these two fields, both encoded as unpadded base64url. The
Worker authorizes only the exact credential ID and Ed25519 public key pair. Add
or remove entries in source and redeploy the Worker.

After a new identity's first successful direct nearby key request, copy
`identity.credentialId` and `identity.publicKey` from
`${XDG_STATE_HOME:-$HOME/.local/state}/keytap/nearby-identity.json`. That first
pairing must succeed over direct P2P because the identity cannot use TURN until
it has been added and redeployed. `keytap init --force` creates a different
identity, so replace its allowlist entry before expecting TURN to work again.

## How TURN authorization works

TURN is never requested until direct ICE fails. The approval device then signs
a fresh room-bound challenge, and the Worker verifies the allowlisted
credential and public key before minting one cached, short-lived credential
set. The signed proof also becomes the bearer capability required by both peers
to download that credential set, so the QR alone cannot consume TURN quota. The
requested registration or named-key ceremony follows after the relay connects.
