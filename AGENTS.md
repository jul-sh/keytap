# Agents

## Local Secrets

Run `./distribution/setup-signing.sh` to set up local signing secrets (Developer ID certificate and provisioning profile). It decrypts age-encrypted secrets from the `secrets/` directory and installs them into a temporary keychain.

Requires `AGE_SECRET_KEY` environment variable (or reads from macOS Keychain via `distribution/get-age-key.sh`).

Use `./distribution/setup-signing.sh --cleanup` to remove the temporary keychain.
