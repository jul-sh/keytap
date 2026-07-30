#!/usr/bin/env bash
# Regenerate the embedded `keytap --help` block in README.md so the docs can
# never drift from the CLI. Rewrites everything between the HELP:BEGIN and
# HELP:END markers with the live help output.
#
# Usage:
#   scripts/update-readme-help.sh          # rewrite README.md in place
#   scripts/update-readme-help.sh --check  # exit 1 if README is stale (no write)
set -euo pipefail

cd "$(dirname "$0")/.."

README="README.md"
BEGIN="<!--HELP:BEGIN-->"
END="<!--HELP:END-->"

cargo build -q -p keytap

help_output="$(./target/debug/keytap --help)"

# Assemble the replacement block: markers + a fenced code block, generated in a
# temp file so we can splice it around the existing markers with awk.
block_file="$(mktemp)"
trap 'rm -f "$block_file"' EXIT
{
  echo "$BEGIN"
  echo '```'
  printf '%s\n' "$help_output"
  echo '```'
  echo "$END"
} > "$block_file"

if ! grep -qF "$BEGIN" "$README" || ! grep -qF "$END" "$README"; then
  echo "error: $README is missing the $BEGIN / $END markers" >&2
  exit 2
fi

# Replace the marker block (inclusive) with the freshly generated one.
new_readme="$(mktemp)"
trap 'rm -f "$block_file" "$new_readme"' EXIT
awk -v begin="$BEGIN" -v end="$END" -v blockfile="$block_file" '
  $0 ~ begin { while ((getline line < blockfile) > 0) print line; skip=1; next }
  $0 ~ end   { skip=0; next }
  !skip      { print }
' "$README" > "$new_readme"

if [ "${1:-}" = "--check" ]; then
  if ! diff -u "$README" "$new_readme" >/dev/null; then
    echo "README help block is stale. Run: scripts/update-readme-help.sh" >&2
    diff -u "$README" "$new_readme" >&2 || true
    exit 1
  fi
  echo "README help block is up to date."
else
  mv "$new_readme" "$README"
  trap 'rm -f "$block_file"' EXIT
  echo "Updated $README help block."
fi
