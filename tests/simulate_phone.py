#!/usr/bin/env python3
"""
Simulate the phone side of the nearby relay flow.
Reads the QR URL from stdin (or as arg), extracts the config,
generates an X25519 keypair, does ECDH + HKDF + AES-GCM,
and POSTs the encrypted blob to the relay.

Usage:
    echo "<url>" | python3 tests/simulate_phone.py
    python3 tests/simulate_phone.py "<url>"
"""

import base64
import hashlib
import json
import os
import sys
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

RELAY_URL = os.environ.get("TAPKEY_RELAY_URL", "http://tapkey-relay.julsh.workers.dev")
# Convert ws:// to http:// for POST requests
if RELAY_URL.startswith("ws://"):
    RELAY_URL = RELAY_URL.replace("ws://", "http://", 1)
elif RELAY_URL.startswith("wss://"):
    RELAY_URL = RELAY_URL.replace("wss://", "https://", 1)


def b64url_decode(s: str) -> bytes:
    # Add padding
    s += "=" * ((4 - len(s) % 4) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def main():
    if len(sys.argv) > 1:
        url = sys.argv[1].strip()
    else:
        url = input().strip()

    # Extract fragment
    parsed = urllib.parse.urlparse(url)
    fragment = parsed.fragment
    params = urllib.parse.parse_qs(fragment)
    cfg_b64 = params["cfg"][0]

    cfg_json = b64url_decode(cfg_b64).decode()
    cfg = json.loads(cfg_json)

    print(f"Config: operation={cfg['o']}, name={cfg.get('n', 'N/A')}, session={cfg['s'][:8]}...")

    session_id = cfg["s"]
    cli_pub_bytes = b64url_decode(cfg["k"])

    # Generate phone keypair
    phone_sk = X25519PrivateKey.generate()
    phone_pk = phone_sk.public_key()
    phone_pk_bytes = phone_pk.public_bytes_raw()

    # ECDH
    cli_pub = X25519PublicKey.from_public_bytes(cli_pub_bytes)
    shared_secret = phone_sk.exchange(cli_pub)

    # HKDF-SHA256
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=session_id.encode(),
        info=b"tapkey:e2e:v1",
    )
    aes_key = hkdf.derive(shared_secret)

    # Build payload — fake PRF output (32 bytes of 0x42)
    fake_prf = bytes([0x42] * 32)
    payload = json.dumps({
        "credentialId": b64url_encode(b"fake-credential-id"),
        "prfFirst": b64url_encode(fake_prf),
    })

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
        headers={
            "Content-Type": "application/json",
            "Origin": "https://tapkey.jul.sh",
            "User-Agent": "Mozilla/5.0 tapkey-test",
        },
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
