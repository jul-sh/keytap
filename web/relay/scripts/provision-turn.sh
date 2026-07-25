#!/usr/bin/env bash
set -euo pipefail

readonly DEFAULT_ACCOUNT_ID="28fb983f1661b4931e2ceec7f9a0b8c2"
readonly TURN_KEY_NAME="keytap-production"

: "${CLOUDFLARE_PROVISION_TOKEN:?set a one-time Cloudflare token with Calls Write}"
: "${CLOUDFLARE_API_TOKEN:?set the Worker deployment token used by Wrangler}"

CLOUDFLARE_ACCOUNT_ID="${CLOUDFLARE_ACCOUNT_ID:-$DEFAULT_ACCOUNT_ID}"
export CLOUDFLARE_ACCOUNT_ID

for command_name in curl jq nix; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    echo "missing required command: $command_name" >&2
    exit 1
  fi
done

response="$({
  curl --fail-with-body --silent --show-error \
    --request POST \
    "https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/calls/turn_keys" \
    --header "Authorization: Bearer ${CLOUDFLARE_PROVISION_TOKEN}" \
    --header "Content-Type: application/json" \
    --data "{\"name\":\"${TURN_KEY_NAME}\"}"
} 2>&1)" || {
  echo "Cloudflare did not create the TURN key:" >&2
  echo "$response" >&2
  exit 1
}

turn_key_id="$(jq -er 'select(.success == true) | .result.uid | select(type == "string" and length == 32)' <<<"$response")"
turn_key_api_token="$(jq -er 'select(.success == true) | .result.key | select(type == "string" and length == 64)' <<<"$response")"
unset response

script_dir="$(
  unset CDPATH
  cd -- "$(dirname -- "$0")"
  pwd
)"
relay_dir="$(dirname -- "$script_dir")"

(
  cd "$relay_dir"
  TURN_KEY_ID="$turn_key_id" TURN_KEY_API_TOKEN="$turn_key_api_token" \
    jq -cn '{
      TURN_KEY_ID: env.TURN_KEY_ID,
      TURN_KEY_API_TOKEN: env.TURN_KEY_API_TOKEN
    }' \
    | nix run nixpkgs#wrangler -- secret bulk
)

unset turn_key_api_token
echo "Created ${TURN_KEY_NAME} (${turn_key_id}) and stored both Worker secrets."
echo "Deploy the Worker, then run a forced-relay test from two separate networks."
