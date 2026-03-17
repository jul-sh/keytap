'use strict';

const RELAY_URL = 'https://tapkey-relay.julsh.workers.dev';

const elements = {
  title: document.getElementById('title'),
  summary: document.getElementById('summary'),
  details: document.getElementById('details'),
  panelNote: document.getElementById('panel-note'),
  steps: document.getElementById('steps'),
  callout: document.getElementById('callout'),
  start: document.getElementById('start'),
  status: document.getElementById('status'),
  bridgeHint: document.getElementById('bridge-hint'),
  result: document.getElementById('result'),
  resultValue: document.getElementById('result-value'),
  copyBtn: document.getElementById('copy-btn')
};

const bridge = (() => {
  const handler = window.webkit?.messageHandlers?.tapkey;
  if (handler && typeof handler.postMessage === 'function') {
    return { kind: 'native', handler };
  }
  return { kind: 'missing' };
})();

let runState = { kind: 'loading' };

const textDecoder = new TextDecoder();

function updateStatus(message) {
  elements.status.textContent = message;
}

function setButton(label, disabled) {
  elements.start.textContent = label;
  elements.start.disabled = disabled;
}

function decodeBase64URL(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}

function encodeBase64URL(value) {
  const bytes = value instanceof Uint8Array
    ? value
    : value instanceof ArrayBuffer
      ? new Uint8Array(value)
      : new Uint8Array(value.buffer, value.byteOffset || 0, value.byteLength);

  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function readConfigToken() {
  const hash = location.hash.startsWith('#') ? location.hash.slice(1) : location.hash;
  const hashParams = new URLSearchParams(hash);
  if (hashParams.has('cfg')) {
    return hashParams.get('cfg');
  }

  const queryParams = new URLSearchParams(location.search);
  return queryParams.get('cfg');
}

function readRequiredString(source, key) {
  if (typeof source[key] !== 'string' || source[key].length === 0) {
    throw new Error(`Missing ${key} in nearby flow config.`);
  }
  return source[key];
}

function readOptionalString(source, key) {
  if (!(key in source) || source[key] === null || source[key] === undefined) {
    return null;
  }
  if (typeof source[key] !== 'string' || source[key].length === 0) {
    throw new Error(`Invalid ${key} in nearby flow config.`);
  }
  return source[key];
}

function parseSession() {
  const token = readConfigToken();
  if (!token) {
    return { kind: 'missing-config' };
  }

  try {
    const raw = JSON.parse(textDecoder.decode(decodeBase64URL(token)));

    // Detect relay mode: compact field names with session/key fields
    const isRelay = typeof raw.s === 'string' && typeof raw.k === 'string';

    if (isRelay) {
      return parseRelaySession(raw);
    }

    // Legacy/native mode: verbose field names
    return parseLegacySession(raw);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return { kind: 'invalid-config', message };
  }
}

function parseRelaySession(raw) {
  const operation = raw.o === 'r' ? 'register' : 'assert';
  const sessionId = readRequiredString(raw, 's');
  const cliPubKeyBase64URL = readRequiredString(raw, 'k');
  const prfSaltBase64URL = readRequiredString(raw, 'p');
  const challengeBase64URL = readRequiredString(raw, 'c');

  const relay = { sessionId, cliPubKeyBase64URL };

  if (operation === 'register') {
    return {
      kind: 'configured',
      flow: {
        kind: 'register',
        rpId: 'tapkey.jul.sh',
        challengeBase64URL,
        prfSaltBase64URL,
        userIDBase64URL: readRequiredString(raw, 'u'),
        userName: readRequiredString(raw, 'un'),
        relay
      }
    };
  }

  return {
    kind: 'configured',
    flow: {
      kind: 'assert',
      rpId: 'tapkey.jul.sh',
      challengeBase64URL,
      prfSaltBase64URL,
      keyName: raw.n || 'default',
      preferredCredentialIDBase64URL: readOptionalString(raw, 'cid'),
      relay
    }
  };
}

function parseLegacySession(raw) {
  const operation = readRequiredString(raw, 'operation');
  const common = {
    rpId: readRequiredString(raw, 'rpId'),
    challengeBase64URL: readRequiredString(raw, 'challengeBase64URL'),
    prfSaltBase64URL: readRequiredString(raw, 'prfSaltBase64URL')
  };

  switch (operation) {
    case 'register':
      return {
        kind: 'configured',
        flow: {
          kind: 'register',
          ...common,
          userIDBase64URL: readRequiredString(raw, 'userIDBase64URL'),
          userName: readRequiredString(raw, 'userName')
        }
      };
    case 'assert':
      return {
        kind: 'configured',
        flow: {
          kind: 'assert',
          ...common,
          keyName: readRequiredString(raw, 'keyName'),
          preferredCredentialIDBase64URL: readOptionalString(raw, 'preferredCredentialIDBase64URL')
        }
      };
    default:
      return { kind: 'invalid-config', message: `Unsupported nearby flow operation: ${operation}` };
  }
}

// ─── E2E Encryption (X25519 + HKDF + AES-256-GCM) ───

async function checkX25519Support() {
  try {
    await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
    return true;
  } catch {
    return false;
  }
}

async function generateX25519Keypair() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'X25519' },
    false,
    ['deriveBits']
  );
  const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
  return { keyPair, publicKeyBytes: new Uint8Array(publicKeyRaw) };
}

async function deriveSharedKey(phonePrivateKey, cliPubKeyBytes, sessionId) {
  // Import CLI's public key
  const cliPubKey = await crypto.subtle.importKey(
    'raw',
    cliPubKeyBytes,
    { name: 'X25519' },
    false,
    []
  );

  // ECDH shared secret
  const sharedBits = await crypto.subtle.deriveBits(
    { name: 'X25519', public: cliPubKey },
    phonePrivateKey,
    256
  );

  // HKDF: salt = sessionId bytes, info = "tapkey:e2e:v1"
  const ikm = await crypto.subtle.importKey(
    'raw',
    sharedBits,
    'HKDF',
    false,
    ['deriveKey']
  );

  const encoder = new TextEncoder();
  return crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: encoder.encode(sessionId),
      info: encoder.encode('tapkey:e2e:v1')
    },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );
}

async function encryptAndPost(aesKey, payload, sessionId, phonePubKeyBytes) {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const plaintext = encoder.encode(JSON.stringify(payload));

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    aesKey,
    plaintext
  );

  const body = JSON.stringify({
    pk: encodeBase64URL(phonePubKeyBytes),
    nonce: encodeBase64URL(nonce),
    ciphertext: encodeBase64URL(ciphertext)
  });

  const response = await fetch(`${RELAY_URL}/relay/${sessionId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body
  });

  if (!response.ok) {
    throw new Error(`Relay POST failed: ${response.status} ${response.statusText}`);
  }
}

// ─── Result handling ───

function showResult(payload) {
  elements.result.hidden = false;
  elements.resultValue.textContent = JSON.stringify(payload, null, 2);

  elements.copyBtn.addEventListener('click', () => {
    navigator.clipboard.writeText(JSON.stringify(payload)).then(() => {
      elements.copyBtn.textContent = 'Copied';
      setTimeout(() => { elements.copyBtn.textContent = 'Copy'; }, 2000);
    }, () => {
      elements.copyBtn.textContent = 'Failed';
      setTimeout(() => { elements.copyBtn.textContent = 'Copy'; }, 2000);
    });
  });
}

function postToTapkey(payload) {
  if (bridge.kind === 'native') {
    bridge.handler.postMessage(JSON.stringify(payload));
    return;
  }

  showResult(payload);
}

function describeError(error, flowKind) {
  const code = error && typeof error === 'object' && 'name' in error ? error.name : null;
  const fallback = error instanceof Error ? error.message : String(error);

  switch (code) {
    case 'AbortError':
      return { code, message: 'The passkey request was interrupted before it finished.' };
    case 'ConstraintError':
      return { code, message: 'This passkey provider cannot satisfy tapkey\'s passkey requirements.' };
    case 'InvalidStateError':
      return flowKind === 'register'
        ? { code, message: 'A tapkey passkey may already exist on this authenticator.' }
        : { code, message: 'The selected passkey could not be used for this request.' };
    case 'NotAllowedError':
      return flowKind === 'register'
        ? { code, message: 'Passkey creation was cancelled or timed out.' }
        : { code, message: 'Passkey approval was cancelled or timed out.' };
    case 'NotSupportedError':
      return { code, message: fallback || 'This nearby passkey flow does not support WebAuthn PRF.' };
    case 'SecurityError':
      return { code, message: 'This page is not allowed to use passkeys for tapkey.jul.sh.' };
    default:
      return { code, message: fallback };
  }
}

function showFailure(failure, flowKind) {
  runState = { kind: 'ready', flowKind };
  updateStatus(failure.message);
  setButton('Try again', false);
  postToTapkey({ type: 'error', code: failure.code, message: failure.message });
}

async function showSuccess(payload, relay) {
  runState = { kind: 'finished' };

  if (relay) {
    updateStatus('Encrypting and sending to CLI…');
    setButton('Sending…', true);

    try {
      const hasX25519 = await checkX25519Support();
      if (!hasX25519) {
        updateStatus('This browser does not support X25519. Cannot send result to CLI.');
        showResult(payload);
        return;
      }

      const { keyPair, publicKeyBytes } = await generateX25519Keypair();
      const cliPubKeyBytes = decodeBase64URL(relay.cliPubKeyBase64URL);
      const aesKey = await deriveSharedKey(keyPair.privateKey, cliPubKeyBytes, relay.sessionId);

      await encryptAndPost(aesKey, payload, relay.sessionId, publicKeyBytes);

      updateStatus('Sent! You can close this page.');
      setButton('Done', true);
    } catch (error) {
      updateStatus(`Failed to send: ${error.message}`);
      showResult(payload);
    }
    return;
  }

  if (bridge.kind === 'native') {
    updateStatus('Handing the result back to tapkey…');
  } else {
    updateStatus('Done. Copy the result below.');
  }
  postToTapkey(payload);
}

// ─── WebAuthn requests ───

function createRegisterRequest(flow) {
  return {
    publicKey: {
      challenge: decodeBase64URL(flow.challengeBase64URL),
      rp: {
        id: flow.rpId,
        name: 'tapkey'
      },
      user: {
        id: decodeBase64URL(flow.userIDBase64URL),
        name: flow.userName,
        displayName: flow.userName
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 }
      ],
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required'
      },
      attestation: 'none',
      timeout: 120000,
      extensions: {
        prf: {
          eval: { first: decodeBase64URL(flow.prfSaltBase64URL) }
        }
      }
    }
  };
}

function createAssertRequest(flow) {
  const request = {
    publicKey: {
      challenge: decodeBase64URL(flow.challengeBase64URL),
      rpId: flow.rpId,
      userVerification: 'required',
      timeout: 120000,
      extensions: {
        prf: {
          eval: { first: decodeBase64URL(flow.prfSaltBase64URL) }
        }
      }
    }
  };

  if (flow.preferredCredentialIDBase64URL) {
    request.publicKey.allowCredentials = [
      {
        type: 'public-key',
        id: decodeBase64URL(flow.preferredCredentialIDBase64URL)
      }
    ];
  }

  return request;
}

async function runRegister(flow) {
  updateStatus('Waiting for passkey creation…');
  const credential = await navigator.credentials.create(createRegisterRequest(flow));
  if (!credential) {
    throw new Error('Passkey creation returned no credential.');
  }

  const extensionResults = credential.getClientExtensionResults?.() || {};
  const prfSupported = extensionResults.prf?.enabled === true;
  if (!prfSupported) {
    throw Object.assign(
      new Error('The passkey was created, but this authenticator does not support WebAuthn PRF.'),
      { name: 'NotSupportedError' }
    );
  }

  const payload = {
    type: 'register-success',
    credentialId: encodeBase64URL(credential.rawId)
  };

  await showSuccess(payload, flow.relay);
}

async function runAssertion(flow) {
  updateStatus('Waiting for passkey approval…');
  const credential = await navigator.credentials.get(createAssertRequest(flow));
  if (!credential) {
    throw new Error('Passkey approval returned no credential.');
  }

  const extensionResults = credential.getClientExtensionResults?.() || {};
  const prfFirst = extensionResults.prf?.results?.first;
  if (!prfFirst) {
    throw Object.assign(
      new Error('PRF output was not returned by this passkey flow.'),
      { name: 'NotSupportedError' }
    );
  }

  const payload = {
    type: 'assert-success',
    credentialId: encodeBase64URL(credential.rawId),
    prfFirst: encodeBase64URL(prfFirst)
  };

  await showSuccess(payload, flow.relay);
}

function configureFlow(flow) {
  if (!window.PublicKeyCredential || !navigator.credentials) {
    runState = { kind: 'blocked' };
    elements.summary.textContent = 'This browser does not support WebAuthn.';
    elements.details.textContent = 'The passkey ceremony requires a browser with WebAuthn and PRF support.';
    elements.callout.textContent = 'Try a recent version of Chrome or Safari.';
    elements.callout.hidden = false;
    setButton('Unavailable', true);
    updateStatus('WebAuthn is not available.');
    return;
  }

  const isRelay = !!flow.relay;

  switch (flow.kind) {
    case 'register':
      elements.title.textContent = 'Create the tapkey passkey';
      elements.summary.textContent = 'Create the passkey once, then tapkey can recover the same keys anywhere that passkey is available.';
      elements.details.textContent = isRelay
        ? 'Scanned from a QR code. The result will be encrypted and sent back to the CLI.'
        : 'If you do not want the passkey stored on this device, pick a nearby device in the passkey sheet.';
      elements.panelNote.textContent = 'The passkey becomes the root for every key tapkey derives later.';
      elements.steps.innerHTML = isRelay
        ? [
            '<li>Tap continue.</li>',
            '<li>Approve the passkey creation.</li>',
            '<li>The encrypted result is sent back to the CLI automatically.</li>'
          ].join('')
        : [
            '<li>Tap continue.</li>',
            '<li>Choose where the passkey should live.</li>',
            '<li>Approve the passkey creation.</li>'
          ].join('');
      elements.callout.hidden = true;
      setButton('Continue to register', false);
      updateStatus('Ready.');
      runState = { kind: 'ready', flowKind: 'register' };
      elements.start.addEventListener('click', async () => {
        if (runState.kind !== 'ready' || runState.flowKind !== 'register') return;
        runState = { kind: 'running', flowKind: 'register' };
        setButton('Registering…', true);
        try {
          await runRegister(flow);
        } catch (error) {
          showFailure(describeError(error, 'register'), 'register');
        }
      }, { once: false });
      return;
    case 'assert':
      elements.title.textContent = isRelay ? 'Approve on this device' : 'Use your tapkey passkey';
      elements.summary.textContent = isRelay
        ? 'Approve the passkey on this phone. The key will be encrypted and sent back to the CLI.'
        : 'Recover the key you asked for. If the passkey is on another device, choose a nearby device when prompted.';
      elements.details.textContent = `Requested key name: ${flow.keyName}`;
      elements.panelNote.textContent = 'Same passkey, same name, same derived key.';
      elements.steps.innerHTML = isRelay
        ? [
            '<li>Tap continue.</li>',
            '<li>Approve with your passkey.</li>',
            '<li>The encrypted result is sent to the CLI automatically.</li>'
          ].join('')
        : [
            '<li>Tap continue.</li>',
            '<li>Approve on this device or choose a nearby device.</li>',
            '<li>tapkey receives the PRF result and derives the key locally.</li>'
          ].join('');
      elements.callout.textContent = isRelay
        ? 'The PRF output is end-to-end encrypted. Only the CLI that showed the QR code can decrypt it.'
        : 'Only the requested secret is handed back to tapkey. The passkey itself stays with the authenticator that approved the request.';
      elements.callout.hidden = false;
      setButton('Continue to authenticate', false);
      updateStatus('Ready.');
      runState = { kind: 'ready', flowKind: 'assert' };
      elements.start.addEventListener('click', async () => {
        if (runState.kind !== 'ready' || runState.flowKind !== 'assert') return;
        runState = { kind: 'running', flowKind: 'assert' };
        setButton('Waiting…', true);
        try {
          await runAssertion(flow);
        } catch (error) {
          showFailure(describeError(error, 'assert'), 'assert');
        }
      }, { once: false });
      return;
    default:
      break;
  }
}

function showMissingConfig() {
  elements.title.textContent = 'No session config.';
  elements.summary.textContent = 'This page runs the passkey ceremony for tapkey, but no session config was provided. If you expected authentication to happen, something went wrong.';
  elements.details.textContent = '';
  elements.panelNote.textContent = '';
  elements.steps.innerHTML = '<li>Make sure tapkey is up to date.</li><li>Run <code>tapkey register</code> or <code>tapkey derive</code> again.</li>';
  elements.callout.hidden = true;
  setButton('Unavailable', true);
  updateStatus('');
}

function showInvalidConfig(message) {
  elements.title.textContent = 'Something went wrong.';
  elements.summary.textContent = 'tapkey opened this page with a config it can\'t understand.';
  elements.details.textContent = message;
  elements.panelNote.textContent = '';
  elements.steps.innerHTML = '<li>Make sure tapkey is up to date.</li><li>Try the command again.</li>';
  elements.callout.hidden = true;
  setButton('Unavailable', true);
  updateStatus(message);
  postToTapkey({ type: 'error', code: 'InvalidConfig', message });
}

function main() {
  const session = parseSession();
  switch (session.kind) {
    case 'missing-config':
      showMissingConfig();
      return;
    case 'invalid-config':
      showInvalidConfig(session.message);
      return;
    case 'configured':
      configureFlow(session.flow);
      return;
    default:
      showInvalidConfig('Unknown nearby flow session state.');
  }
}

main();
