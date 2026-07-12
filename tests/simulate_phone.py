#!/usr/bin/env python3
"""
Simulate the phone side of the nearby relay flow.
Reads the QR URL from stdin (or as arg), fetches the session config from the
relay (or extracts the legacy inline config), generates an X25519 keypair,
does ECDH + HKDF + AES-GCM, and POSTs the encrypted blob to the relay.

Usage:
    echo "<url>" | python3 tests/simulate_phone.py
    python3 tests/simulate_phone.py "<url>" [flags]

Like the real page, the simulator sends the assertion first (with
`follow: true` when the CLI advertised an opt-in window via `w`) and then
tells the CLI it is finished ({type: "done"}), releasing it immediately.

--remember          post-auth opt-in: remember-pending, then a second
                    ceremony's payload with `remember: true` (same passkey)
--wrong-key         like --remember, but the first approval comes from a
                    different passkey (must be refused, window stays open,
                    a correct follow-up then stores)
--legacy-remember   old cached page: `remember: true` rides inside the FIRST
                    payload, no `follow`, no done
--no-follow         new-CLI/old-page unticked: no `follow`, no done; the CLI
                    must exit without lingering
--no-done           sends `follow` but goes silent, exercising the CLI's
                    bounded opt-in window
--done-textplain    send done with Content-Type text/plain (the pagehide
                    beacon encoding)
--garbage           inject undecryptable junk before and after the payload
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

# Sent for realism; the relay itself never inspects them (it CORS-echoes the
# Origin and JSON-parses the body regardless of Content-Type).
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


def post_raw(cfg: dict, body: str, label: str, content_type: str = "application/json") -> None:
    """POST one wire message to the relay."""
    headers = dict(BROWSER_HEADERS, **{"Content-Type": content_type})
    req = urllib.request.Request(
        f"{RELAY_URL}/relay/{cfg['s']}",
        data=body.encode(),
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            print(f"Relay response ({label}): {resp.status} {resp.read().decode()}")
    except urllib.error.HTTPError as e:
        print(f"Relay error ({label}): {e.code} {e.read().decode()}")
        sys.exit(1)


def encrypt_and_post(cfg: dict, payload: dict, content_type: str = "application/json") -> None:
    """Encrypt one message under a fresh phone keypair (as the page does for
    every POST) and deliver it through the relay."""
    session_id = cfg["s"]
    cli_pub = X25519PublicKey.from_public_bytes(b64url_decode(cfg["k"]))

    phone_sk = X25519PrivateKey.generate()
    phone_pk_bytes = phone_sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    shared_secret = phone_sk.exchange(cli_pub)

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=session_id.encode(),
        info=b"keytap:e2e:v1",
    ).derive(shared_secret)

    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, json.dumps(payload).encode(), None)

    body = json.dumps({
        "pk": b64url_encode(phone_pk_bytes),
        "nonce": b64url_encode(nonce),
        "ciphertext": b64url_encode(ciphertext),
    })
    post_raw(cfg, body, payload.get("type", "?"), content_type)


def ceremony_payload(cfg: dict, remember: bool, credential: bytes = b"fake-credential-id") -> dict:
    """A fake ceremony result: fixed credential, fixed PRF output (32 × 0x42),
    so repeated ceremonies look like the same passkey — as they would be."""
    payload = {"credentialId": b64url_encode(credential)}
    if cfg["o"] == "r":
        payload["type"] = "register-success"
    else:
        payload["type"] = "assert-success"
        payload["prfFirst"] = b64url_encode(bytes([0x42] * 32))
    if remember:
        payload["remember"] = True
    return payload


def main():
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    url = args[0].strip() if args else input().strip()

    cfg = fetch_config(url)
    offered = bool(cfg.get("m"))
    print(
        f"Config: operation={cfg['o']}, name={cfg.get('n', 'N/A')}, "
        f"session={cfg['s'][:8]}..., offers_remember={offered}"
    )
    if ("--remember" in flags or "--legacy-remember" in flags) and not offered:
        print("note: sending remember=true even though the CLI didn't offer it (m absent)")

    if "--garbage" in flags:
        # A bystander who knows the session id pushes junk; the CLI must
        # keep waiting through it, before and after the real payload.
        post_raw(cfg, json.dumps({"pk": "AAAA", "nonce": "AAAA", "ciphertext": "AAAA"}), "garbage")

    # First message: the ceremony result. `follow` announces this page can
    # send follow-ups (the CLI only lingers for pages that say so); legacy
    # pages instead smuggle the remember request into this payload.
    first = ceremony_payload(cfg, remember="--legacy-remember" in flags)
    if not {"--legacy-remember", "--no-follow"} & flags and cfg.get("w"):
        first["follow"] = True
    encrypt_and_post(cfg, first)

    if "--garbage" in flags:
        # Valid JSON (the relay forwards it) but not a decryptable envelope.
        post_raw(cfg, json.dumps({"pk": "AAAA", "nonce": "AAAA", "ciphertext": "!!!"}), "garbage")

    if "--remember" in flags or "--wrong-key" in flags:
        # The post-auth opt-in: tapping the button announces the pending
        # ceremony (a liveness probe that also extends the CLI's window),
        # then the second ceremony's result carries the request.
        encrypt_and_post(cfg, {"type": "remember-pending"})
        if "--wrong-key" in flags:
            # Approval from a DIFFERENT passkey: the CLI must refuse it and
            # keep the window open, so a correct follow-up still lands.
            encrypt_and_post(cfg, ceremony_payload(cfg, remember=True, credential=b"some-other-passkey"))
        encrypt_and_post(cfg, ceremony_payload(cfg, remember=True))
    elif "--no-done" in flags or "--legacy-remember" in flags or "--no-follow" in flags:
        # Go silent; the CLI's bounded window (if any) is on its own.
        pass
    else:
        # The page's "finished" signal releases the CLI immediately. The
        # pagehide beacon sends it as text/plain (beacons cannot preflight);
        # exercise that encoding.
        content_type = "text/plain" if "--done-textplain" in flags else "application/json"
        encrypt_and_post(cfg, {"type": "done"}, content_type)

    print("Phone side complete — CLI should have received and decrypted the blob.")


if __name__ == "__main__":
    main()
