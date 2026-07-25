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
   public key in the QR-code URL fragment
2. the phone verifies the CLI's signature over the complete WebRTC offer,
   including its DTLS fingerprint; peers connect directly when possible and
   use Cloudflare Realtime TURN otherwise
3. on first use, a commit–reveal exchange gives the phone and CLI the same two
   words; the phone sends its WebAuthn result immediately, but the CLI buffers
   it and refuses to use or pin it until you confirm those words in the terminal
4. that one passkey approval derives both the named key and a separate, stable
   signing identity; the phone signs the exact result, and the CLI verifies it
   and pins the identity
5. later requests require a fresh signature from that pinned identity and skip
   the word comparison

`keytap init` also uses the comparison. WebAuthn may omit PRF output during
registration, so init first stores only the credential ID; the first derivation
pins its signing identity with the same approval that derives the requested
key. Rejecting the words may leave an unused passkey on the phone, but sends no
credential ID or key to the CLI. `keytap init --force` intentionally replaces
the local identity and derived-key root.

The public key is 43 base64url characters, so the complete production URL is
only 74 characters (`https://keytap.jul.sh/nearby#k=...`). The rendezvous ID is
derived from it; it is not an additional QR payload.

After a nearby derivation delivers its key, the page can offer a **Remember on
this machine** action. It performs a second passkey approval on the same
connection; the CLI stores the key only if it matches the first result, with no
second QR scan (see [Skipping repeated prompts](#skipping-repeated-prompts)).

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

- By default keytap derives on demand, writes to stdout, and exits. Nearby auth
  stores only a public identity pin in
  `~/.local/state/keytap/nearby-identity.json`, never a PRF output or derived key.
- Remembering is the explicit exception. It stores the named key on this
  machine until you forget it or replace the passkey; any process running as
  your user may then be able to use it without a ceremony. See
  [Skipping repeated prompts](#skipping-repeated-prompts).
- `keytap init` replaces the root, wipes remembered entries, and makes the new
  persisted identity generation authoritative for remembered-key lookup.
- If you save the output, pipe it into another tool, or import it into an agent, that destination now holds the key and must be trusted accordingly.
- The PRF inputs are public and derived from the key name. They provide stable derivation and domain separation, not secrecy.
- Replacing the registered passkey changes every key derived from it. Treat the passkey as the root of your derived identities.

### Auth via nearby phone (fallback)

When keytap authenticates via your phone, additional trust considerations apply:

- **You trust the web page served to your phone.** The code served by
  `keytap.jul.sh` sees the QR public key and both WebAuthn PRF outputs. A
  compromised page can steal the named key and identity seed, then impersonate
  that passkey in nearby flows until `keytap init --force`. The URL fragment is
  absent from the initial HTTP request and Referer, but loaded JavaScript sees it.
- **The QR value is public, not a shared secret.** Keep the code in view only
  long enough to connect. Someone who reads it can derive the rendezvous ID,
  race a fake phone, learn request metadata, or deny service, but cannot forge
  the CLI's signed offer. Before an identity is pinned, the two-word
  comparison detects a fake phone. The commitments fix both nonces before
  reveal and bind the words to the exact request and WebRTC session. The 22-bit
  phrase has a 1 in 4,194,304 collision chance per independently committed
  attempt; approving a mismatch or repeated attempts increases risk. Once
  pinned, the phone must instead prove the trusted private identity key. The
  Worker receives only a hash-derived rendezvous ID, not the QR public key.
- **The nearby identity pin is local public state, not a secret.** It is written
  atomically with owner-only permissions (and honors `$XDG_STATE_HOME`); init
  refuses to overwrite a concurrently changed pin. Local software able to
  replace the file can reset trust. The intentional reset is `keytap init --force`.
- **The signaling Worker is not trusted with peer identity or key material.**
  It sees a derived rendezvous ID, the signed offer, the unsigned answer,
  SDP/ICE metadata, IP addresses, and timing. It can block, delay, replay, or
  race/replace the answer, but cannot alter the signed offer. The CLI does not
  use a first result until the words match; later, the pinned identity rejects
  substitution.
- **Cloudflare TURN is not trusted with plaintext.** Direct peer-to-peer ICE is
  preferred; when TURN is necessary, Cloudflare relays DTLS-encrypted WebRTC
  packets. It can observe metadata or deny service, but payload confidentiality
  does not depend on the TURN operator being honest.
- **TURN credential issuance is intentionally public.** Keytap has no account
  check, rate limit, or cache. A caller can open an arbitrary signaling room
  and repeatedly request fresh, short-lived credentials charged to this
  deployment. This quota and availability risk is explicitly accepted. It
  does not reveal Keytap key material or let the caller decrypt another WebRTC
  session.
- **Legacy `#s` relay links use the older X25519 protocol.** The CLI and page
  display a one-time host public key; compare the full values before approving.
  That comparison detects relay key substitution, but the legacy path does not
  provide the automatic passkey identity pinning described here and remains a
  transitional compatibility route.

The signed offer authenticates its DTLS fingerprint. Every initial pairing
binds the QR key, both full SDPs, exact ceremony request, and full 256-bit
comparison digest. For derivation, the phone also signs the credential, named
PRF result, and identity key; those keys use WebAuthn PRF's domain-separated
`first` and `second` outputs from the same approval. After WebAuthn, the phone
sends the result over the authenticated WebRTC channel. The CLI buffers it and
only makes it available to verification, use, or pinning after terminal
confirmation. Fresh signing keys, challenges, commitments, and WebRTC sessions
make captured results unusable in another command. The initial ceremony fails
closed on a comparison mismatch, rejection, malformed message, disconnect, or
timeout; the separately acknowledged remember follow-up may be retried after
returning a different credential or result.

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

Create a Realtime TURN key in the Cloudflare dashboard, then install its **Turn
Token ID** and **API Token** as Worker secrets. The API token is long-lived and
must never be committed or sent to a client. See Cloudflare's
[TURN credential guide](https://developers.cloudflare.com/realtime/turn/generate-credentials/).

```bash
cd web/relay
nix run nixpkgs#wrangler -- secret put TURN_KEY_ID
nix run nixpkgs#wrangler -- secret put TURN_KEY_API_TOKEN
nix run nixpkgs#wrangler -- deploy
```

Wrangler uses the account ID in `wrangler.toml`; authenticate it with a Worker
deploy token via `CLOUDFLARE_API_TOKEN`. At runtime, public
`GET /v2/signal/:rendezvous/turn` requests mint a fresh 1,200-second credential.
There are no accounts, rate limits, or credential caches, and credentials are
never persisted. After the provider responds, the Durable Object rechecks that
the exact room generation is still active before returning it; this prevents a
delayed request from succeeding after expiry or room recreation, but is not
user authorization. The deployment explicitly accepts TURN quota abuse.

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
