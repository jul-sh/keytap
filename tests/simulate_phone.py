#!/usr/bin/env python3
"""
Simulate the phone side of the nearby relay flow.
Reads the QR URL from stdin (or as arg), fetches the session config from the
relay (or extracts the legacy inline config), generates an X25519 keypair,
does ECDH + HKDF + AES-GCM, and POSTs the encrypted blob to the relay.

Usage:
    echo "<url>" | python3 tests/simulate_phone.py
    python3 tests/simulate_phone.py "<url>" [--remember]

--remember simulates ticking the page's "remember this key on that machine"
checkbox: the encrypted payload carries `remember: true`, which the CLI only
honors when its config offered it (`m`).
"""

import base64
import json
import os
import re
import sys
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

RELAY_URL = os.environ.get("KEYTAP_RELAY_URL", "https://keytap-relay.julsh.workers.dev")
# Convert ws:// to http:// for GET/POST requests
if RELAY_URL.startswith("ws://"):
    RELAY_URL = RELAY_URL.replace("ws://", "http://", 1)
elif RELAY_URL.startswith("wss://"):
    RELAY_URL = RELAY_URL.replace("wss://", "https://", 1)

# The relay rejects requests that don't look like they come from the web page.
BROWSER_HEADERS = {
    "Content-Type": "application/json",
    "Origin": "https://keytap.jul.sh",
    "User-Agent": "Mozilla/5.0 keytap-test",
}


def b64url_decode(s: str) -> bytes:
    # Add padding
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def fetch_config(url: str) -> dict:
    """The session config, from the legacy inline fragment or the relay."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.fragment)

    if "cfg" in params:  # legacy: whole config inline in the fragment
        return json.loads(b64url_decode(params["cfg"][0]).decode())

    # Current: a session ID, either as /n/<id> or the redirected #s=<id>
    if "s" in params:
        session_id = params["s"][0]
    else:
        match = re.search(r"/n/([A-Za-z0-9_-]+)", parsed.path)
        if not match:
            sys.exit(f"can't find a session ID in URL: {url}")
        session_id = match.group(1)

    req = urllib.request.Request(f"{RELAY_URL}/relay/{session_id}", headers=BROWSER_HEADERS)
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read().decode())


def main():
    args = [a for a in sys.argv[1:] if a != "--remember"]
    remember = "--remember" in sys.argv[1:]
    url = args[0].strip() if args else input().strip()

    cfg = fetch_config(url)
    offered = bool(cfg.get("m"))
    print(
        f"Config: operation={cfg['o']}, name={cfg.get('n', 'N/A')}, "
        f"session={cfg['s'][:8]}..., offers_remember={offered}"
    )
    if remember and not offered:
        print("note: sending remember=true even though the CLI didn't offer it (m absent)")

    session_id = cfg["s"]
    cli_pub_bytes = b64url_decode(cfg["k"])

    # Generate phone keypair
    phone_sk = X25519PrivateKey.generate()
    phone_pk = phone_sk.public_key()
    phone_pk_bytes = phone_pk.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    # ECDH
    cli_pub = X25519PublicKey.from_public_bytes(cli_pub_bytes)
    shared_secret = phone_sk.exchange(cli_pub)

    # HKDF-SHA256
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=session_id.encode(),
        info=b"keytap:e2e:v1",
    )
    aes_key = hkdf.derive(shared_secret)

    # Build payload — fake PRF output (32 bytes of 0x42)
    fake_prf = bytes([0x42] * 32)
    body_fields = {
        "credentialId": b64url_encode(b"fake-credential-id"),
    }
    if cfg["o"] != "r":
        body_fields["prfFirst"] = b64url_encode(fake_prf)
    if remember:
        body_fields["remember"] = True
    payload = json.dumps(body_fields)

    # AES-256-GCM encrypt
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, payload.encode(), None)

    # POST to relay
    body = json.dumps({
        "pk": b64url_encode(phone_pk_bytes),
        "nonce": b64url_encode(nonce),
        "ciphertext": b64url_encode(ciphertext),
    })

    req = urllib.request.Request(
        f"{RELAY_URL}/relay/{session_id}",
        data=body.encode(),
        headers=BROWSER_HEADERS,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            print(f"Relay response: {resp.status} {resp.read().decode()}")
    except urllib.error.HTTPError as e:
        print(f"Relay error: {e.code} {e.read().decode()}")
        sys.exit(1)

    print("Phone side complete — CLI should have received and decrypted the blob.")


if __name__ == "__main__":
    main()
