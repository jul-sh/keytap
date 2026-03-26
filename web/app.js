'use strict';

import init, {
  registrationConfig,
  assertionConfig,
  deriveRawKey,
  formatPrivateKey,
  formatPublicKey,
  prfSaltForName,
} from './pkg/keytap_web.js';

import { PRIVATE_FORMATS, PUBLIC_FORMATS } from './state.js';

const textDecoder = new TextDecoder();

// ── DOM ──

const el = {
  page: document.getElementById('page'),
  flowSelect: document.getElementById('flow-select'),
  keyNameGroup: document.getElementById('key-name-group'),
  keyNameInput: document.getElementById('key-name'),
  formatGroup: document.getElementById('format-group'),
  formatSelect: document.getElementById('format-select'),
  actionBtn: document.getElementById('action-btn'),
  status: document.getElementById('status'),
  resultSection: document.getElementById('result-section'),
  resultOutput: document.getElementById('result-output'),
  copyBtn: document.getElementById('copy-btn'),
  downloadBtn: document.getElementById('download-btn'),
  newBtn: document.getElementById('new-btn'),
};

// ── State ──

let state = { kind: 'loading' };

function setState(next) {
  state = next;
  render();
}

// ── Helpers ──

function encodeBase64URL(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function decodeBase64URL(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

function randomChallenge() {
  return crypto.getRandomValues(new Uint8Array(32));
}

// ── Credential ID persistence ──

const CRED_STORAGE_KEY = 'keytap:credentialId';

function loadCredentialId() {
  try {
    return localStorage.getItem(CRED_STORAGE_KEY);
  } catch {
    return null;
  }
}

function saveCredentialId(idBase64URL) {
  try {
    localStorage.setItem(CRED_STORAGE_KEY, idBase64URL);
  } catch {
    // Ignore storage errors
  }
}

// ── WebAuthn flows ──

async function runRegister() {
  const config = registrationConfig();
  const challenge = randomChallenge();
  const prfSalt = new Uint8Array(config.default_prf_salt);

  const credential = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { id: config.rp_id, name: 'keytap' },
      user: {
        id: new Uint8Array(config.user_id),
        name: config.user_name,
        displayName: config.user_name,
      },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
      },
      attestation: 'none',
      timeout: 120000,
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  });

  if (!credential) throw new Error('Passkey creation returned no credential.');

  const extResults = credential.getClientExtensionResults?.() || {};
  if (!extResults.prf?.enabled) {
    throw Object.assign(
      new Error('The passkey was created, but this authenticator does not support WebAuthn PRF.'),
      { name: 'NotSupportedError' }
    );
  }

  const credId = encodeBase64URL(new Uint8Array(credential.rawId));
  saveCredentialId(credId);
  return { credentialId: credId };
}

async function runDerive(keyName, format) {
  const credIdB64 = loadCredentialId();
  const preferredCredId = credIdB64 ? Array.from(decodeBase64URL(credIdB64)) : null;
  const config = assertionConfig(keyName, preferredCredId);

  const challenge = randomChallenge();
  const prfSalt = new Uint8Array(config.prf_salt);

  const request = {
    publicKey: {
      challenge,
      rpId: config.rp_id,
      userVerification: 'required',
      timeout: 120000,
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  };

  if (config.preferred_credential_id) {
    request.publicKey.allowCredentials = [
      { type: 'public-key', id: new Uint8Array(config.preferred_credential_id) },
    ];
  }

  const credential = await navigator.credentials.get(request);
  if (!credential) throw new Error('Passkey approval returned no credential.');

  const extResults = credential.getClientExtensionResults?.() || {};
  const prfFirst = extResults.prf?.results?.first;
  if (!prfFirst) {
    throw Object.assign(
      new Error('PRF output was not returned by this passkey flow.'),
      { name: 'NotSupportedError' }
    );
  }

  // Cache credential ID for next time
  saveCredentialId(encodeBase64URL(new Uint8Array(credential.rawId)));

  const rawKey = deriveRawKey(new Uint8Array(prfFirst));
  const output = formatPrivateKey(new Uint8Array(rawKey), format);
  const outputStr = textDecoder.decode(new Uint8Array(output));
  return { output: outputStr, format, keyName };
}

async function runPublicKey(keyName, format) {
  const credIdB64 = loadCredentialId();
  const preferredCredId = credIdB64 ? Array.from(decodeBase64URL(credIdB64)) : null;
  const config = assertionConfig(keyName, preferredCredId);

  const challenge = randomChallenge();
  const prfSalt = new Uint8Array(config.prf_salt);

  const request = {
    publicKey: {
      challenge,
      rpId: config.rp_id,
      userVerification: 'required',
      timeout: 120000,
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  };

  if (config.preferred_credential_id) {
    request.publicKey.allowCredentials = [
      { type: 'public-key', id: new Uint8Array(config.preferred_credential_id) },
    ];
  }

  const credential = await navigator.credentials.get(request);
  if (!credential) throw new Error('Passkey approval returned no credential.');

  const extResults = credential.getClientExtensionResults?.() || {};
  const prfFirst = extResults.prf?.results?.first;
  if (!prfFirst) {
    throw Object.assign(
      new Error('PRF output was not returned by this passkey flow.'),
      { name: 'NotSupportedError' }
    );
  }

  saveCredentialId(encodeBase64URL(new Uint8Array(credential.rawId)));

  const rawKey = deriveRawKey(new Uint8Array(prfFirst));
  const output = formatPublicKey(new Uint8Array(rawKey), format);
  return { output, format, keyName };
}

// ── Render ──

function populateFormats(flowKind) {
  el.formatSelect.innerHTML = '';
  const formats = flowKind === 'public-key' ? PUBLIC_FORMATS : PRIVATE_FORMATS;
  for (const fmt of formats) {
    const opt = document.createElement('option');
    opt.value = fmt;
    opt.textContent = fmt;
    el.formatSelect.appendChild(opt);
  }
}

function render() {
  el.resultSection.hidden = true;
  el.actionBtn.disabled = false;

  switch (state.kind) {
    case 'unsupported':
      el.status.textContent = state.reason;
      el.actionBtn.disabled = true;
      el.actionBtn.textContent = 'Unavailable';
      break;

    case 'ready': {
      const flow = state.flow;
      el.keyNameGroup.hidden = flow.kind === 'register';
      el.formatGroup.hidden = flow.kind === 'register';
      el.status.textContent = 'Ready.';
      switch (flow.kind) {
        case 'register':
          el.actionBtn.textContent = 'Register passkey';
          break;
        case 'derive':
          el.actionBtn.textContent = 'Derive key';
          break;
        case 'public-key':
          el.actionBtn.textContent = 'Get public key';
          break;
      }
      break;
    }

    case 'running':
      el.status.textContent = 'Waiting for passkey\u2026';
      el.actionBtn.disabled = true;
      el.actionBtn.textContent = 'Working\u2026';
      break;

    case 'succeeded':
      el.status.textContent = 'Done.';
      el.actionBtn.hidden = true;
      el.resultSection.hidden = false;
      el.resultOutput.textContent = state.result.output;
      break;

    case 'failed':
      el.status.textContent = state.message;
      el.actionBtn.textContent = 'Try again';
      break;
  }
}

// ── Event handlers ──

function currentFlow() {
  const flowKind = el.flowSelect.value;
  if (flowKind === 'register') return { kind: 'register' };
  const keyName = el.keyNameInput.value || 'default';
  const format = el.formatSelect.value;
  return { kind: flowKind, keyName, format };
}

el.flowSelect.addEventListener('change', () => {
  const flow = currentFlow();
  el.keyNameGroup.hidden = flow.kind === 'register';
  el.formatGroup.hidden = flow.kind === 'register';
  populateFormats(flow.kind);
  setState({ kind: 'ready', flow });
});

el.actionBtn.addEventListener('click', async () => {
  if (state.kind !== 'ready' && state.kind !== 'failed') return;

  const flow = currentFlow();
  setState({ kind: 'running', flow });

  try {
    let result;
    switch (flow.kind) {
      case 'register':
        result = await runRegister();
        setState({ kind: 'succeeded', result: { output: `Passkey registered.\nCredential ID: ${result.credentialId}` } });
        return;
      case 'derive':
        result = await runDerive(flow.keyName, flow.format);
        break;
      case 'public-key':
        result = await runPublicKey(flow.keyName, flow.format);
        break;
    }
    setState({ kind: 'succeeded', result });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    setState({ kind: 'failed', flow, message });
  }
});

el.copyBtn.addEventListener('click', async () => {
  if (state.kind !== 'succeeded') return;
  try {
    await navigator.clipboard.writeText(state.result.output);
    el.copyBtn.textContent = 'Copied';
    setTimeout(() => { el.copyBtn.textContent = 'Copy'; }, 1500);
  } catch {
    el.status.textContent = 'Copy failed. Select the text manually.';
  }
});

el.downloadBtn.addEventListener('click', () => {
  if (state.kind !== 'succeeded') return;
  const blob = new Blob([state.result.output], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  const name = state.result.keyName || 'keytap';
  const ext = state.result.format === 'ssh' ? '' : `.${state.result.format || 'txt'}`;
  a.href = url;
  a.download = `${name}${ext}`;
  a.click();
  URL.revokeObjectURL(url);
});

el.newBtn.addEventListener('click', () => {
  el.actionBtn.hidden = false;
  const flow = currentFlow();
  populateFormats(flow.kind);
  setState({ kind: 'ready', flow });
});

// ── Init ──

async function main() {
  await init();
  const flow = currentFlow();
  populateFormats(flow.kind);
  if (!window.PublicKeyCredential || !navigator.credentials) {
    setState({ kind: 'unsupported', reason: 'WebAuthn is not available in this browser.' });
  } else {
    setState({ kind: 'ready', flow });
  }
}

main().catch((err) => {
  el.status.textContent = `Failed to initialize: ${err.message}`;
});
