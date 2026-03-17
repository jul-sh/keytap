'use strict';

const RELAY_URL = 'https://tapkey-relay.julsh.workers.dev';

/** @param {string} value */
function decodeBase64URL(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

/** @param {Uint8Array|ArrayBuffer} buf */
function encodeBase64URL(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function parseConfig() {
  const hash = location.hash.startsWith('#') ? location.hash.slice(1) : '';
  const token = new URLSearchParams(hash).get('cfg');
  if (!token) throw new Error('No config in URL fragment.');

  const raw = JSON.parse(new TextDecoder().decode(decodeBase64URL(token)));
  return {
    operation: raw.o === 'r' ? 'register' : 'assert',
    sessionId: raw.s,
    cliPubKey: raw.k,
    prfSalt: raw.p,
    challenge: raw.c,
    keyName: raw.n || 'default',
    userId: raw.u,
    userName: raw.un,
  };
}

// ─── E2E Encryption ───

async function encryptAndPost(payload, config) {
  const keyPair = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);

  const cliPubKey = await crypto.subtle.importKey('raw', decodeBase64URL(config.cliPubKey), { name: 'X25519' }, false, []);
  const sharedBits = await crypto.subtle.deriveBits({ name: 'X25519', public: cliPubKey }, keyPair.privateKey, 256);

  const ikm = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  const enc = new TextEncoder();
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode(config.sessionId), info: enc.encode('tapkey:e2e:v1') },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, enc.encode(JSON.stringify(payload)));

  const resp = await fetch(`${RELAY_URL}/relay/${config.sessionId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      pk: encodeBase64URL(new Uint8Array(publicKeyRaw)),
      nonce: encodeBase64URL(nonce),
      ciphertext: encodeBase64URL(ciphertext),
    }),
  });
  if (!resp.ok) throw new Error(`Relay POST failed: ${resp.status}`);
}

// ─── WebAuthn ───

async function runRegister(config) {
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: decodeBase64URL(config.challenge),
      rp: { id: 'tapkey.jul.sh', name: 'tapkey' },
      user: { id: decodeBase64URL(config.userId), name: config.userName, displayName: config.userName },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      attestation: 'none',
      timeout: 120000,
      extensions: { prf: { eval: { first: decodeBase64URL(config.prfSalt) } } },
    },
  });

  const prf = credential.getClientExtensionResults()?.prf;
  if (!prf?.enabled) throw new Error('Passkey created but this authenticator does not support PRF.');

  return { type: 'register-success', credentialId: encodeBase64URL(credential.rawId) };
}

async function runAssertion(config) {
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: decodeBase64URL(config.challenge),
      rpId: 'tapkey.jul.sh',
      userVerification: 'required',
      timeout: 120000,
      extensions: { prf: { eval: { first: decodeBase64URL(config.prfSalt) } } },
    },
  });

  const prfFirst = credential.getClientExtensionResults()?.prf?.results?.first;
  if (!prfFirst) throw new Error('PRF output was not returned.');

  return { type: 'assert-success', credentialId: encodeBase64URL(credential.rawId), prfFirst: encodeBase64URL(prfFirst) };
}

// ─── UI ───

const $ = id => document.getElementById(id);

async function main() {
  const status = $('status');
  const btn = $('start');

  let config;
  try {
    config = parseConfig();
  } catch (e) {
    status.textContent = e.message;
    return;
  }

  const isRegister = config.operation === 'register';
  $('title').textContent = isRegister ? 'Create the tapkey passkey' : 'Approve on this device';
  $('summary').textContent = isRegister
    ? 'Create the passkey once, then tapkey can recover the same keys anywhere.'
    : `Approve to derive key: ${config.keyName}`;
  status.textContent = 'Ready.';
  btn.textContent = isRegister ? 'Register' : 'Authenticate';
  btn.disabled = false;

  btn.addEventListener('click', async () => {
    btn.disabled = true;
    status.textContent = isRegister ? 'Waiting for passkey creation…' : 'Waiting for passkey approval…';

    try {
      const payload = isRegister ? await runRegister(config) : await runAssertion(config);
      status.textContent = 'Encrypting and sending…';
      await encryptAndPost(payload, config);
      status.textContent = 'Sent! You can close this page.';
      btn.textContent = 'Done';
    } catch (e) {
      status.textContent = e.message;
      btn.textContent = 'Try again';
      btn.disabled = false;
    }
  });
}

main();
