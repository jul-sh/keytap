# Passkeys that turn into real keys.

<img src="macos/keytap.icon/Assets/icon.png" width="128" alt="keytap icon" />

`keytap` derives reproducible `age` identities, SSH keys, and 32-byte secrets
from a passkey using WebAuthn PRF.

> **Pre-release:** I use Keytap for my own projects, but it is not stable yet.
> Expect breaking changes, and do not make it the only way to recover important
> secrets.

Same passkey + same name = same key. Different names produce independent keys.
By default, no derived key is stored.

Try it without installing at [keytap.jul.sh](https://keytap.jul.sh).

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

Options
  --nearby  Use the QR-code nearby-phone flow instead of native passkey UI
  --prompt  Run a passkey ceremony even under $CI (the QR code lands in the job log)

Skip repeated prompts for a key: `keytap remember NAME` (see `keytap remember --help`).
Holds that expire instead (ssh-agent, TTLs): see `keytap reveal --help`.
CI (headless, $CI set): keys come from `$KEYTAP_KEY_<NAME>` — see `keytap reveal --help`.
Run `keytap <COMMAND> --help` for the full details of any command.
```
<!--HELP:END-->


## How it works

1. `keytap init` registers a passkey for `keytap.jul.sh`.
2. A command asks that passkey for deterministic PRF output scoped to a name.
3. `keytap` formats the resulting key material as `age`, SSH, hex, or base64.

Use names such as `github`, `backup`, or `deploy` for domain separation. Run
the same command on another machine with the same passkey to reproduce the key.
Use `keytap remember NAME` when you prefer local storage to repeated prompts.

## Platform model

- **macOS:** native WebAuthn, normally approved with Touch ID or the system
  passkey UI.
- **Other platforms:** scan a QR code to use a nearby phone. The QR authenticates
  an encrypted WebRTC connection; Cloudflare TURN relays it when direct ICE
  fails. On first use, confirm the same two words in the terminal. Later uses
  authenticate the pinned passkey identity without another comparison.

Pass `--nearby` to any installed command that needs a ceremony to request the
phone flow explicitly.

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

`keytap` is a convenience tool, not a high-assurance key manager. You trust your
passkey provider, WebAuthn PRF, and the `keytap.jul.sh` relying party.

- By default, keys are derived on demand, written to stdout, and not stored.
- Anything receiving stdout receives the key and must be trusted.
- `remember` stores a named key locally and lets processes running as you use it
  without another ceremony.
- Replacing the passkey changes every derived key and clears remembered keys.
- Key names and PRF inputs provide domain separation, not secrecy.

For stronger isolation, use per-device SSH keys or hardware-backed tools such
as [FIDO2 SSH keys](https://developers.yubico.com/SSH/Securing_git_with_SSH_and_FIDO2.html),
[`age-keygen`](https://github.com/FiloSottile/age), or
[`age-plugin-yubikey`](https://github.com/str4d/age-plugin-yubikey).

### Auth via nearby phone (fallback)

- **Trust the scanned QR.** It identifies the receiving CLI. A substituted QR
  sends the approved PRF result to an attacker; terminal word comparison cannot
  undo that disclosure. Scan directly from the terminal running `keytap`.
- **Trust the phone web page.** It sees the PRF outputs and nearby identity seed.
- The QR is public. Someone who reads it can race the phone, observe request
  metadata, or deny service, but cannot forge the CLI's signed offer.

## Skipping repeated prompts

`keytap remember` stores one named key on the current machine. It has no TTL;
the key stays until you forget it or replace the passkey.

```bash
keytap remember deploy      # one ceremony; 'deploy' stops prompting on this machine
keytap reveal deploy        # instant, no prompt
keytap remembered           # list remembered names (never key material)
keytap forget deploy        # back to prompting; or: keytap forget --all
```

`remember` uses macOS Keychain or desktop Linux Secret Service when available.
Otherwise it writes an owner-only file at
`~/.local/state/keytap/remembered.json` (honoring `$XDG_STATE_HOME`). The file is
not encrypted; treat it like an SSH private key. Any process running as you may
be able to use remembered keys without another ceremony.

Nearby auth offers the same option before approval. Choose **Use once** to store
nothing, or **Use and remember** to store the key on the CLI machine using that
same passkey approval.

For an expiring SSH hold, use `ssh-agent`:

```bash
eval "$(ssh-agent -s)"
keytap reveal ha --as ssh | ssh-add -t 900 -   # one auth, 15-minute hold
```

For reuse within one script, keep the key in a variable and clear it afterward:

```bash
KEY=$(keytap reveal deploy --as hex)
use "$KEY"; use "$KEY"
unset KEY
```

Whatever holds the key must be trusted.

## CI

Under `$CI`, `keytap` refuses to start an interactive ceremony. Provide each
derived key through an environment variable instead:

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

- The value must be `keytap reveal <name> --as age` output.
- The variable is `KEYTAP_KEY_` plus the uppercased name, with non-alphanumeric
  characters replaced by `_` (`my-app` → `KEYTAP_KEY_MY_APP`).
- A present variable wins over remembered keys and ceremonies. Invalid or empty
  values fail instead of falling back to a prompt.
- A leaked value compromises that name permanently; retire the name. It does
  not reveal the passkey root or keys under other names.

Use `--prompt` only for an attended CI run.

## Cloudflare TURN deployment (maintainers)

Create a Realtime TURN key, then install its **Turn Token ID** and **API Token**
as Worker secrets. Never commit or send the API token to a client. See the
[TURN credential guide](https://developers.cloudflare.com/realtime/turn/generate-credentials/).

```bash
cd web/relay
nix run nixpkgs#wrangler -- secret put TURN_KEY_ID
nix run nixpkgs#wrangler -- secret put TURN_KEY_API_TOKEN
nix run nixpkgs#wrangler -- deploy
```

Authenticate Wrangler with `CLOUDFLARE_API_TOKEN`; the account ID is in
`wrangler.toml`. TURN credentials are public, short-lived, and not persisted.
There is no account-level authorization or quota protection.

## Tips

### Streaming

`encrypt` and `decrypt` stream stdin to stdout:

```bash
printf '%s' "$SECRET" | keytap encrypt backup > secret.age   # stdin → stdout
keytap decrypt backup < secret.age | load-into-env           # → a consumer, no temp file
```

### Use with the `age` CLI

Derived keys also work with the regular `age` CLI:

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

## License

MIT
