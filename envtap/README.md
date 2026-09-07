# envtap

`.env` files are plaintext and cannot be committed. Envtap keeps the same
variables in `tap.env`, encrypted per value, committed to Git, with a
grant for each person and CI job that may read them. Your key comes from a
passkey that already syncs across your devices, so there is no key file to
lose or leak.

```text
#: envtap v1 3kq…
#: grant jul age1jul… <wrapped key>
#: grant sam age1sam… <wrapped key>
#: grant github-actions age1ci… <wrapped key>

DATABASE_URL=envtap:v1:Ae3…
STRIPE_KEY=envtap:v1:9bW…
```

Names and grants are readable in diffs. Values change one line at a time, so
branches that touch different variables merge.

## Install

envtap is the `keytap` executable invoked under this name. Installing
[Keytap](../README.md#install) sets up both commands; with Nix:

```bash
nix profile install github:jul-sh/keytap#envtap
```

## Usage

```bash
envtap login                 # creates your passkey the first time
envtap import .env           # or: envtap set DATABASE_URL
git add tap.env
git commit -m "Add environment"

envtap run -- npm run dev
```

```text
Usage: envtap [OPTIONS] <COMMAND>

Commands:
  login       Log in with your passkey, or remember a key file with -i
  logout      Forget your key on this machine
  status      Show the file, your key, your access, variables, and grants
  set         Set a variable from a hidden prompt or stdin
  get         Print one value
  unset       Remove a variable from future revisions
  run         Run a command with the variables in its environment
  export      Print every variable decrypted
  import      Import variables from a plaintext .env file
  public-key  Print your public key for someone to grant
  grant       Grant a public key access
  revoke      Remove access and re-encrypt under a new key
  rotate      Re-encrypt every value under a new key
  grant-ci    Create a key for CI, store it with COMMAND, and grant it access
  setup-git   Configure this Git clone to merge and diff envtap files

Options:
  -f, --file <PATH>      Use this file instead of the nearest tap.env
  -e, --env <ENV>        Use tap.<ENV>.env instead of tap.env
  -i, --identity <PATH>  Decrypt with this age identity file or SSH private key
```

Commands find the nearest `tap.env` in the current directory or a parent,
stopping at the repository root. `envtap set` and `envtap import` create it
when it is missing.

## Login

Your key is Keytap's named key `envtap`. `envtap login` is
`keytap remember envtap`, so one passkey serves every machine and both tools;
`envtap login --new` is `keytap init` first, to create the passkey. On a
machine that cannot use passkeys, a QR code and a one-use link let a device
that can approve instead. Do not share them.

The derived key lives in the OS credential store; `envtap logout` is
`keytap forget envtap`, and `keytap reveal envtap --as age` is your backup.

To use an SSH key or an age identity file instead of a passkey:

```bash
envtap login -i ~/.ssh/id_ed25519
```

## Share

Sam prints a public key, and you grant it:

```console
sam$ envtap public-key
age1sam…
```

```bash
envtap grant sam age1sam…
git commit -am "Grant Sam access"
```

An SSH public key works too, so a teammate can be granted from
`~/.ssh/id_ed25519.pub` without installing anything first:

```bash
envtap grant sam ssh-ed25519 AAAA…
```

When someone leaves:

```bash
envtap revoke sam
git commit -am "Revoke Sam's access"
```

`revoke` re-encrypts every value under a new key that Sam never had. Values
already committed remain readable to Sam in Git history, so rotate any that
matter.

## Environments

`tap.production.env` is a separate file with its own grants:

```bash
envtap -e production set DATABASE_URL
envtap -e production grant deploy age1deploy…
envtap -e production run -- npm start
```

## Git

```bash
envtap setup-git
git commit -am "Merge envtap files"
```

This registers a merge driver and a diff textconv for this clone and lists
envtap files in `.gitattributes`. Branches that changed different variables
then merge cleanly, a variable changed on both sides is named as a conflict
to fix with `envtap set`, and `git diff` shows values you can decrypt.

## CI

```bash
envtap grant-ci github-actions -- gh secret set ENVTAP_IDENTITY
git commit -am "Grant GitHub Actions access"
```

```yaml
- name: Test
  run: envtap run -- npm test
  env:
    ENVTAP_IDENTITY: ${{ secrets.ENVTAP_IDENTITY }}
```

`grant-ci` sends the new key to the storage command through stdin and grants
it only if that command succeeds. In CI, `envtap run` reads `ENVTAP_IDENTITY`
and removes it before starting the command.

## Format

`tap.env` is a dotenv file. Lines that start with `#:` are Envtap's: the
first names the format and a random file ID, and each `grant` line carries a
label, a public key, and the file's data key wrapped to that public key with
[age](https://age-encryption.org). Each encrypted value is ChaCha20-Poly1305
under the data key with the file ID and the variable name as associated
data, so a value cannot be altered, moved to another name, or copied to
another file without detection. Comments and blank lines are preserved.

## Notes

- macOS 15+ and Linux.
- Applications read normal environment variables.
- Run only trusted repository code: `envtap run` gives its command every
  decrypted value, and an encrypted file can be copied to another checkout.
- A key file remembered with `envtap login -i` is referenced by path from
  `$XDG_STATE_HOME/envtap/identity-file`; the file itself is never copied.
