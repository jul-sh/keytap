# Share an encrypted `.env` through Git

Think of [`age`](https://github.com/FiloSottile/age) as a lock that can have one
keyhole per developer. Each developer has their own private key; nobody shares
a password or private key. The identity can be managed by Keytap or by another
age-compatible tool.

A normal repository looks like this:

```text
.env                  local plaintext; ignored by Git
.env.age              encrypted copy; committed
age-recipients.txt    developers' public keys; committed
.gitignore
```

Public keys start with `age1` and are safe to commit. Private keys start with
`AGE-SECRET-KEY-1` and must never be committed or shared.

## Set it up once

Each developer needs their own age identity and sends the maintainer its public
recipient—the line beginning with `age1`. How they create and keep the identity
is their choice.

As one option, a developer who uses Keytap can get their recipient with:

```bash
keytap public YOUR_KEY_NAME --as age
```

`YOUR_KEY_NAME` is that developer's choice. It does not need to match anyone
else's; they only need to reuse their chosen name when they decrypt. A developer
using another age-compatible tool simply provides that identity's `age1...`
recipient instead.

Collect the printed public keys in `age-recipients.txt`:

```text
# Alice
age1alice...

# Bob
age1bob...
```

This is a normal text file with one public key per line. The `.txt` extension
is optional; blank lines and `#` comments are allowed. Commit this file.

Configure `.gitignore`:

```gitignore
.env*
!.env.example
!.env.age
```

Encrypt the working `.env` for exactly the listed developers:

```bash
keytap encrypt YOUR_KEY_NAME --no-self -R age-recipients.txt < .env > .env.age
git add .gitignore age-recipients.txt .env.age
git commit -m "Add encrypted development environment"
```

`-R` means "encrypt for everyone in this recipients file." `--no-self` stops
Keytap from silently adding the person who ran the command; the file is then
the complete access list. Never add `.env` to Git.

## Daily use

After cloning or pulling, turn the committed encrypted file back into the
local plaintext file using whichever tool owns your identity.

For a Keytap-managed identity:

```bash
keytap decrypt YOUR_KEY_NAME < .env.age > .env
```

For an identity file managed by the regular age CLI:

```bash
age --decrypt -i ~/.config/age/keys.txt .env.age > .env
```

Then start the app:

```bash
npm run dev
```

When a secret changes, edit `.env`, encrypt it again with the same command,
and commit only `.env.age`. Teammates pull and decrypt again. Keytap users can
optionally run `keytap remember YOUR_KEY_NAME` once to stop repeated prompts on
that machine; read
[Remembered keys and CI](../README.md#remembered-keys-and-ci) first.

## Add or remove a developer

- **Add:** get their `age1...` public recipient, add it to
  `age-recipients.txt`, re-encrypt `.env.age`, and commit both files. Keytap
  users get it with `keytap public YOUR_KEY_NAME --as age`.
- **Remove:** delete their public key, re-encrypt, and rotate the actual API
  keys/passwords inside `.env`. Removing a recipient cannot erase plaintext or
  old Git versions they already had.

## Why age?

Age is a small, standard file-encryption format built for explicit public
recipients, multiple recipients, and stdin/stdout pipelines. That maps directly
to a Git team: public access list in the repository, private keys kept by
developers, encrypted secret file in Git. Keytap includes age support, so
developers do not need a shared password or private key, and each developer
can choose how to manage their own identity.
