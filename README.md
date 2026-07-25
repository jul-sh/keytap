# Passkeys that turn into real keys.

<img src="macos/keytap.icon/Assets/icon.png" width="128" alt="keytap icon" />

`keytap` is a CLI that turns one passkey into unique keys you can reproduce anywhere.

> **Pre-release:** I use Keytap for my own projects, but it is not stable yet.
> Expect breaking changes, and do not make it the only way to recover important
> secrets.

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

No install needed to try it: [keytap.jul.sh](https://keytap.jul.sh) is a terminal running this same CLI, compiled to WebAssembly; every command below works there.

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
CI (headless, $CI set): keys come from `$KEYTAP_KEY_<NAME>` — see `keytap reveal --help`.
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

1. the CLI generates a one-time Ed25519 keypair and puts only its 32-byte
   public key in a QR-code URL fragment
2. you scan the QR code and your phone opens the `keytap` page
3. the CLI signs its complete WebRTC offer; the phone verifies that signature
   before giving the offer, including its DTLS fingerprint, to WebRTC
4. WebRTC connects them directly when possible, with Cloudflare Realtime TURN as a fallback
5. if this machine has not paired with the passkey identity yet, a
   commit–reveal exchange produces the same two words independently on the CLI
   and phone
6. the phone shows those words, completes the passkey ceremony, and holds its
   result locally; there is no confirmation step on the phone
7. once the phone is finished, the CLI gives you two minutes to say whether
   its words exactly match the phone; only an affirmative terminal answer
   signs a one-time release that the phone verifies before sending the held
   result
8. for a derivation, that one passkey approval returns two independent PRF
   outputs: the requested named key and a stable nearby-identity seed
9. the page signs the pairing and exact derivation result with the Ed25519
   identity derived from that seed, and the CLI pins it for later requests
10. on an already-paired machine, the pinned signature authenticates the fresh
    session, so the comparison steps are skipped

The comparison is required for the first nearby derivation on a new machine,
for nearby registration, and once after upgrading an older or `keytap init`
credential-only record into a full identity pin. Registration can only store
the new credential ID portably because WebAuthn permits
[`create()` to omit PRF results](https://w3c.github.io/webauthn/#prf-extension);
it still finishes on the phone before the terminal confirmation. Rejecting the
words can leave an unused passkey on the phone, but its credential ID is not
sent to or stored by the CLI. The next ordinary derivation uses that credential
and establishes its Ed25519 identity with the same single passkey approval that
derives the requested key. Every later nearby derivation must use the pinned
credential and verify a fresh signature before the CLI accepts or prints the
key. `keytap init --force` replaces the local identity record because it
deliberately replaces the root passkey.

The public key is 43 base64url characters, exactly the same payload size as the
old 32-byte capability, so the complete production URL remains only 74
characters (`https://keytap.jul.sh/nearby#k=...`). The rendezvous ID is derived
from it; it is not an additional QR payload.

After the command succeeds, the page can offer a **Remember on this machine**
action. Choosing it performs a second passkey approval over the same data
channel; the CLI stores the key only after that result matches the first
ceremony. It does not require another QR scan
(see [Skipping repeated prompts](#skipping-repeated-prompts)).

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

## Guides

- [Share an encrypted `.env` through Git with multiple developers](docs/team-env.md)

## Security

keytap is a convenience utility, not a high-assurance security tool. It is designed to make passkey-derived keys easy to use across machines. If your threat model involves nation-state adversaries, targeted attacks, or secrets where compromise has severe consequences, use purpose-built tools instead:

- **SSH keys**: Generate directly with `ssh-keygen` and manage per-device keys. Use [FIDO2 resident keys](https://developers.yubico.com/SSH/Securing_git_with_SSH_and_FIDO2.html) on a hardware token for phishing-resistant SSH without syncing private material at all.
- **age encryption**: Generate standalone identities with `age-keygen`. See [age](https://github.com/FiloSottile/age) and [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey) for hardware-bound identities.

keytap ties all derived keys to a single passkey registered under the `keytap.jul.sh` relying party. That means you trust your passkey provider, the WebAuthn PRF extension, and the `keytap.jul.sh` domain. This is a meaningful trust surface that the tools above avoid entirely.

With that said, here is how keytap works within those constraints:

- By default keytap does not sync or cache derived keys. It derives on demand, writes to stdout, and exits. The nearby-phone flow stores one public, human-paired identity in `~/.local/state/keytap/nearby-identity.json`; it never stores a PRF output or derived key there.
- The one explicit exception is remembering — `keytap remember NAME`, or the opt-in remember action on the nearby-phone page: it stores that derived key on this machine, with no TTL, until `keytap forget`, `keytap forget --all`, or passkey replacement. The key lands in a plain file (not encrypted at rest), silently upgraded to the OS keychain when the machine has one (then encrypted at rest by it). Either way, any process running as your user may be able to invoke keytap and use the key without a ceremony.
- Remembered keys are tied to a fingerprint of the registered passkey credential. `keytap init` is a root boundary: it wipes all remembered entries, and the exact persisted identity generation authorizes every lookup. Even if cleanup is interrupted, keys remembered under a replaced passkey are never used.
- If you save the output, pipe it into another tool, or import it into an agent, that destination now holds the key and must be trusted accordingly.
- The PRF inputs are public and derived from the key name. They provide stable derivation and domain separation, not secrecy.
- Replacing the registered passkey changes every key derived from it. Treat the passkey as the root of your derived identities.

### Auth via nearby phone (fallback)

When keytap authenticates via your phone, additional trust considerations apply:

- **You trust the web page served to your phone.** The code served by
  `keytap.jul.sh` sees the public key from the QR and both WebAuthn PRF outputs. A
  compromised page can therefore steal the derived key and the stable nearby
  identity seed, which would let it impersonate that passkey in later nearby
  flows until you replace it with `keytap init --force`. The URL fragment is
  not sent in the initial HTTP request or in a Referer header, but the loaded
  JavaScript necessarily receives it.
- **The QR value is public, not a shared secret.** Keep the code in view only
  long enough to connect because someone who reads it can derive the rendezvous
  ID, race a fake phone, learn request metadata, or deny service. It does not
  give them the CLI's private signing key: they cannot forge its authenticated
  WebRTC offer or the post-WebAuthn release, so they cannot make the legitimate
  phone send its held result. On an unpaired CLI, a fake phone is instead
  detected by the two-word comparison. The commitments bind both parties
  before either reveals its nonce, and the words are bound to the exact request
  and WebRTC session. A fake phone is silently accepted only if its independent
  words collide or the user approves a mismatch. Two BIP39 words carry 22 bits,
  so a fresh adversarial attempt that the user compares and approves has
  probability 1 in 4,194,304 of colliding; repeated approved attempts
  accumulate risk. After a legitimate identity is pinned, substitution is
  rejected because the attacker cannot produce its signature. The Worker
  receives only a hash-derived rendezvous ID rather than the QR public key.
- **The nearby identity pin is local public state, not a secret.** It is written
  atomically with owner-only permissions to
  `~/.local/state/keytap/nearby-identity.json` (and honors `$XDG_STATE_HOME`).
  Init snapshots the exact pre-ceremony revision and refuses to overwrite a
  concurrent init or pairing; an advisory process lock and synced atomic
  publication protect the update itself.
  Local software able to replace that file can reset the trust decision.
  `keytap init --force` is the current intentional reset path; there is no
  separate trust-management command yet. Identity files created by the older
  TOFU protocol are treated as credential-only records and require one
  two-word pairing before they become current identity pins.
- **The signaling Worker is not trusted with peer identity or key material.**
  It sees a derived rendezvous ID, the signed offer, the unsigned answer,
  SDP/ICE metadata, IP addresses, and timing. It can block, delay, replay, or
  race/replace the phone-side answer. It cannot alter the CLI offer or forge a
  release. Before an identity is pinned, the CLI authenticates the phone
  through the two-word comparison; afterward it requires the pinned identity
  signature.
- **Cloudflare TURN is not trusted with plaintext.** Direct peer-to-peer ICE is
  preferred; when TURN is necessary, Cloudflare relays DTLS-encrypted WebRTC
  packets and can observe connection metadata and deny service. Cloudflare
  documents the same distinction in its [TURN FAQ](https://developers.cloudflare.com/realtime/turn/faq/).
  You still trust Cloudflare to operate the service, enforce credential expiry,
  and report usage for billing; payload confidentiality does not depend on the
  TURN operator being honest.
- **TURN credential issuance is intentionally public.** Keytap has no account
  or other entitlement check. Anyone can create an arbitrary rendezvous, have
  two clients claim its public `cli` and `phone` roles, and obtain short-lived
  TURN credentials charged to this deployment. Per-rendezvous caching and the
  per-location IP limiter reduce repeated issuance but neither authorizes a
  user nor imposes an account-wide cap. This quota and availability abuse risk
  is currently accepted. It does not reveal Keytap key material or let a
  credential holder decrypt another WebRTC session; someone who learns a real
  QR value can still race or deny that rendezvous as described above.
- **Legacy `#s` relay links use the older X25519 protocol.** The CLI and page
  display a one-time host public key; compare the full values before approving.
  That comparison detects relay key substitution, but the legacy path does not
  provide the automatic passkey identity pinning described here and remains a
  transitional compatibility route.

For an unpaired request, the CLI signature first authenticates its complete
offer, including the DTLS fingerprint. The commit–reveal context then covers
the fresh QR public key, both complete SDPs, and a canonical encoding of the
exact ceremony request. The identity proof covers the full 256-bit pairing
digest—not merely the two displayed words—plus the WebAuthn challenge,
credential ID, named PRF result, key name, and identity public key. The phone
completes WebAuthn first but holds that result until the sole terminal
confirmation. It then generates a fresh nonce; the CLI signs that nonce, the
session, the full pairing digest, and the exact request. The phone verifies the
signature before release, and the returned result echoes it so the CLI cannot
accept a result queued before confirmation. A rejection, disconnect, or
invalid signature discards an assertion result. For registration it withholds
the credential ID, although WebAuthn may already have created an unused local
passkey. For a paired request, the identity proof is bound directly to the
fresh public key and both SDPs under a distinct protocol tag, so the words are
unnecessary.

Fresh CLI signing keys, WebAuthn challenges, and independently generated
pairing and release nonces make captured messages unusable in another command.
The authenticated data-channel protocol is strictly ordered and one-shot: a
malformed message, commitment mismatch, rejection, or timeout ends the
session, and retrying requires a new QR code. The fixed identity seed comes
from WebAuthn PRF's `second` output while
the named key uses `first`, so both are obtained by the same
`navigator.credentials.get()` approval and are domain-separated.

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

When a command authenticates via the nearby-phone flow, the phone page offers
the same opt-in after the initial result is accepted. Tap it, approve the
second ceremony, and the machine remembers the matching key. The live WebRTC
session is reused, so this takes two approvals but only one QR scan. The phone
reports success only after the machine has actually stored the key; storage
failure is reported as a rejection.

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

## CI

A CI job can hold secrets, but nobody is there to approve a passkey ceremony.
So under `$CI` (which every major CI platform sets) keytap refuses to start
one: a passkey prompt in a headless job is a hung runner, not a question.
A missing key fails the job immediately, with the fix in the message.
(`--prompt` overrides, for the rare run where someone really is watching the
log and wants to scan the QR code out of it.)

Instead, hand the job the derived key through the environment, one variable
per key name:

```bash
# once, on a machine with the passkey
keytap reveal ci --as age | gh secret set KEYTAP_KEY_CI
```

```yaml
# in the job: the same commands as on your machine, no branching
env:
  KEYTAP_KEY_CI: ${{ secrets.KEYTAP_KEY_CI }}
steps:
  - run: keytap decrypt ci < secrets/api-token.age
```

The contract is deliberately narrow:

- **The variable holds exactly the output of `keytap reveal <name> --as age`**
  (`AGE-SECRET-KEY-1…`). One format, and a checksummed one: a mangled secret
  fails loudly at startup instead of quietly becoming a different key. The
  same 32 bytes still come out in every format — `keytap reveal ci --as ssh`
  works from the variable.
- **The variable name** is `KEYTAP_KEY_` plus the key name uppercased, with
  everything outside `A–Z0–9` flattened to `_` (`my-app` →
  `KEYTAP_KEY_MY_APP`). Keep CI-bound key names to lowercase letters, digits,
  and dashes and this is invisible.
- **A set variable always wins** over remembered keys and ceremonies, and a
  set-but-broken variable (empty, wrong encoding) is always a hard error
  naming the variable — never a silent fall-through to a prompt no one can
  answer.
- **If a variable leaks, that name is burned.** The value is the derived key
  for that one name — never the passkey root — and derivation is
  deterministic, so there is no rotating it: retire the name.

## Cloudflare TURN deployment (maintainers)

The production Worker runs in Cloudflare account
`28fb983f1661b4931e2ceec7f9a0b8c2`. Wrangler deployments receive that
non-secret account ID from both the manifest and relay workflow. TURN needs a
separate, long-lived key that must never be shipped to either client. Cloudflare's
[credential guide](https://developers.cloudflare.com/realtime/turn/generate-credentials/)
describes this server-side model.

The encrypted API token already used by CI can deploy the Worker, but it does
**not** have Cloudflare `Calls Write` permission. Keep that least-privilege
token as-is. Production TURN was provisioned on July 24, 2026 with a separate,
account-authorized Cloudflare dashboard session; the long-lived values are
installed only as required Worker secrets and are not present in this repository.

The helper below calls Cloudflare's
[create TURN key API](https://developers.cloudflare.com/api/resources/calls/subresources/turn/methods/create/),
extracts `result.uid` and `result.key`, and writes them directly to the
`TURN_KEY_ID` and `TURN_KEY_API_TOKEN` Worker secrets in one
`wrangler secret bulk` request. It never prints the long-term token, and a
failed upload cannot leave just one of the two values updated. The Wrangler
manifest declares both bindings as required, so deployment fails clearly if
either is missing; see Cloudflare's
[Workers secrets documentation](https://developers.cloudflare.com/workers/configuration/secrets/).
The production Worker is already configured; run this helper again only when
intentionally replacing the TURN key.

```bash
cd web/relay
read -rsp 'Temporary Calls Write token: ' CLOUDFLARE_PROVISION_TOKEN; echo
read -rsp 'Workers Scripts Write deploy token: ' CLOUDFLARE_API_TOKEN; echo
export CLOUDFLARE_PROVISION_TOKEN CLOUDFLARE_API_TOKEN
./scripts/provision-turn.sh
unset CLOUDFLARE_PROVISION_TOKEN CLOUDFLARE_API_TOKEN
```

For local `wrangler dev`, copy `web/relay/.dev.vars.example` to
`web/relay/.dev.vars` and replace both placeholders. `.dev.vars*` and `.env*`
are ignored except for their example files.

The underlying creation request is:

```http
POST https://api.cloudflare.com/client/v4/accounts/28fb983f1661b4931e2ceec7f9a0b8c2/calls/turn_keys
Authorization: Bearer <one-time Calls Write token>
Content-Type: application/json

{"name":"keytap-production"}
```

At runtime the Worker, never a client, exchanges those long-lived values for
one short-lived credential per peer:

```http
POST https://rtc.live.cloudflare.com/v1/turn/keys/{TURN_KEY_ID}/credentials/generate-ice-servers
Authorization: Bearer {TURN_KEY_API_TOKEN}
Content-Type: application/json

{"ttl":1200}
```

The 1,200-second TTL is fixed by the Worker, not supplied by clients. A
credential can be minted only after two clients claim a rendezvous's public
`cli` and `phone` roles, and it is cached once per claimed role for that
rendezvous. The Worker binds sockets, pending requests, and cached credentials
to a persisted session generation. After Cloudflare responds, one storage
transaction rechecks that the exact generation is still live and within its
deadline before storing or returning the credential, so an alarm or recreated
room cannot resurrect expired state. Responses are `no-store`, and the
rendezvous sockets and stored state are erased twenty minutes after the first
peer joins.

These are lifecycle and amplification controls, not user authorization.
Rendezvous creation is public and there is no account-wide issuance cap.
A Workers rate-limit binding allows 20 v2 requests per source address per 60
seconds in each Cloudflare location, but Cloudflare documents that binding as
local and eventually consistent in the
[Workers Rate Limiting API](https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/).
This deployment intentionally accepts the resulting TURN quota and availability
abuse risk. Monitor usage and disable or rotate the TURN key if that becomes
unacceptable.

Clients use normal ICE so a direct connection wins. They accept Cloudflare's
STUN service and TURN endpoints but omit port 53 for non-trickle ICE, because
Cloudflare notes that browsers block that alternate port. The current Rust
client uses `stun:stun.cloudflare.com:3478` and
`turn:turn.cloudflare.com:3478?transport=udp`.

Production verification on July 24, 2026 joined both roles to a live rendezvous
and validated the two distinct short-lived ICE credentials returned for that
room. A second live test used relay-only ICE for both native peers,
authenticated both SDPs through the production Worker, verified
relay candidates on both sides, and delivered a DataChannel marker through
Cloudflare UDP TURN. The full forced-relay path completed in 18.91 seconds.
Testing the browser and CLI from two physically separate networks remains a
useful release check for platform-specific firewall behavior.

As of July 2026, Cloudflare's [TURN pricing](https://developers.cloudflare.com/realtime/turn/faq/)
is the first 1,000 GB per month free across Realtime SFU and TURN, then
$0.05/GB sent from Cloudflare to TURN clients, including TURN overhead.
Ingress is free, and `stun.cloudflare.com` is free and unlimited. Monitor
usage and issued credentials before removing the legacy route; Cloudflare also
documents [credential-abuse monitoring](https://developers.cloudflare.com/realtime/turn/replacing-existing/).

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
