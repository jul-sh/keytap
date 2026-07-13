'use strict';

const RELAY_URL = 'https://keytap-relay.julsh.workers.dev';

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

// ─── DOM ───

const $ = id => document.getElementById(id);

/** Render a message into an element; string parts stay text, {code} parts
 * become <code> spans. Everything goes through textContent. */
function render(el, ...parts) {
  el.textContent = '';
  for (const part of parts) {
    if (typeof part === 'string') {
      el.append(part);
    } else {
      const code = document.createElement('code');
      code.textContent = part.code;
      el.append(code);
    }
  }
}

/** Progress and confirmations. Clears the alert region: the regions are
 * complementary, never additive. */
function say(...parts) {
  $('alert').textContent = '';
  render($('status'), ...parts);
}

/** Failures and expiry. */
function alertUser(...parts) {
  $('status').textContent = '';
  render($('alert'), ...parts);
}

// ─── Session state ───

let config = null;
let sessionId = null;
let expiryTimer = 0;

/**
 * Every phase carries only the data valid in that phase. In particular,
 * retries hold an already-encrypted envelope and the remember offer owns its
 * expiry and pagehide messages.
 * @typedef {
 *   {kind: 'loading'} |
 *   {kind: 'ready', action: 'run'} |
 *   {kind: 'ready', action: 'resend-register', envelope: string} |
 *   {kind: 'ready', action: 'resend-assert', envelope: string, firstResult: FirstResult} |
 *   {kind: 'first-busy'} |
 *   {kind: 'offer', data: OfferData} |
 *   {kind: 'remembering', step: 'probe'|'ceremony', data: OfferData} |
 *   {kind: 'remember-posting', envelope: string} |
 *   {kind: 'remember-retry', envelope: string} |
 *   {kind: 'released'} |
 *   {kind: 'finished'}
 * } Phase
 * @typedef {{rawId: ArrayBuffer, credentialIdB64: string, prfFirstB64: string}} FirstResult
 * @typedef {{
 *   firstResult: FirstResult,
 *   expiryAt: number,
 *   pendingEnvelope: Promise<string>,
 *   doneEnvelope: string|null
 * }} OfferData
 */
/** @type {Phase} */
let phase = { kind: 'loading' };

function markerKey(sid) {
  return `keytap-sent-${sid}`;
}

function setMarker(state) {
  try {
    sessionStorage.setItem(markerKey(sessionId), JSON.stringify({ state, name: config.keyName }));
  } catch { /* storage may be unavailable; the marker is best-effort */ }
}

function getMarker(sid) {
  try {
    return JSON.parse(sessionStorage.getItem(markerKey(sid)));
  } catch {
    return null;
  }
}

// ─── Config ───

function parseRawConfig(raw) {
  return {
    operation: raw.o === 'r' ? 'register' : 'assert',
    sessionId: raw.s,
    cliPubKey: raw.k,
    prfSalt: raw.p,
    challenge: raw.c,
    keyName: raw.n || 'default',
    userId: raw.u,
    userName: raw.un,
    // Legacy capability: the CLI honors a remember request. Old CLIs set
    // it but exit after one message, so it must never gate the offer.
    legacyRemember: !!raw.m,
    // The CLI lingers this many seconds for post-auth follow-ups; the
    // whole opt-in flow is keyed on it.
    windowSecs: typeof raw.w === 'number' && raw.w > 0 ? raw.w : 0,
  };
}

async function fetchConfig() {
  const hash = location.hash.startsWith('#') ? location.hash.slice(1) : '';
  const params = new URLSearchParams(hash);

  // Legacy: inline config
  const token = params.get('cfg');
  if (token) {
    const raw = JSON.parse(new TextDecoder().decode(decodeBase64URL(token)));
    return parseRawConfig(raw);
  }

  const sid = params.get('s');
  if (!sid) throw { kind: 'no-session' };

  let resp;
  try {
    resp = await fetch(`${RELAY_URL}/relay/${sid}`);
  } catch {
    throw { kind: 'network' };
  }
  if (resp.status === 404) throw { kind: 'gone', sid };
  if (!resp.ok) throw { kind: 'network' };
  return parseRawConfig(await resp.json());
}

// ─── Crypto ───

async function encryptEnvelope(payload) {
  const keyPair = await crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']);
  const publicKeyRaw = await crypto.subtle.exportKey('raw', keyPair.publicKey);

  const cliPubKey = await crypto.subtle.importKey('raw', decodeBase64URL(config.cliPubKey), { name: 'X25519' }, false, []);
  const sharedBits = await crypto.subtle.deriveBits({ name: 'X25519', public: cliPubKey }, keyPair.privateKey, 256);

  const ikm = await crypto.subtle.importKey('raw', sharedBits, 'HKDF', false, ['deriveKey']);
  const enc = new TextEncoder();
  const aesKey = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode(config.sessionId), info: enc.encode('keytap:e2e:v1') },
    ikm,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt']
  );

  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aesKey, enc.encode(JSON.stringify(payload)));

  return JSON.stringify({
    pk: encodeBase64URL(new Uint8Array(publicKeyRaw)),
    nonce: encodeBase64URL(nonce),
    ciphertext: encodeBase64URL(ciphertext),
  });
}

function abortAfter(ms) {
  if (typeof AbortSignal.timeout === 'function') return AbortSignal.timeout(ms);
  const controller = new AbortController();
  setTimeout(() => controller.abort(), ms);
  return controller.signal;
}

function post(body, timeoutMs) {
  const options = { method: 'POST', headers: { 'Content-Type': 'application/json' }, body };
  if (timeoutMs) options.signal = abortAfter(timeoutMs);
  return fetch(`${RELAY_URL}/relay/${sessionId}`, options);
}

// ─── WebAuthn ───

async function runRegister() {
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: decodeBase64URL(config.challenge),
      rp: { id: 'keytap.jul.sh', name: 'keytap' },
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

  return credential;
}

/** @param {ArrayBuffer?} allowId pin the sheet to one credential (second ceremony) */
async function runAssertion(allowId) {
  const publicKey = {
    challenge: decodeBase64URL(config.challenge),
    rpId: 'keytap.jul.sh',
    userVerification: 'required',
    timeout: 120000,
    extensions: { prf: { eval: { first: decodeBase64URL(config.prfSalt) } } },
  };
  if (allowId) publicKey.allowCredentials = [{ type: 'public-key', id: allowId }];

  const credential = await navigator.credentials.get({ publicKey });
  const prfFirst = credential.getClientExtensionResults()?.prf?.results?.first;
  if (!prfFirst) throw new Error('PRF output was not returned.');
  return { credential, prfFirst };
}

function isCancel(e) {
  return e && (e.name === 'NotAllowedError' || e.name === 'AbortError');
}

// ─── Offer expiry (page-local; the CLI's window is the real clock) ───

function armExpiry() {
  if (phase.kind !== 'offer') return;
  phase.data.expiryAt = Date.now() + Math.max(config.windowSecs - 10, 5) * 1000;
  scheduleExpiryCheck();
}

function scheduleExpiryCheck() {
  if (phase.kind !== 'offer' && phase.kind !== 'remembering') return;
  clearTimeout(expiryTimer);
  expiryTimer = setTimeout(checkExpiry, Math.max(phase.data.expiryAt - Date.now(), 0) + 20);
}

function checkExpiry() {
  if (phase.kind === 'remembering') {
    // Never expire mid-ceremony or mid-POST; look again shortly.
    expiryTimer = setTimeout(checkExpiry, 1000);
    return;
  }
  if (phase.kind !== 'offer') return;
  if (Date.now() >= phase.data.expiryAt) {
    expireOffer(true);
  } else {
    scheduleExpiryCheck();
  }
}

/** @param {boolean} releaseCli post the done envelope so the terminal frees
 * up as this guidance renders (skipped when the CLI already 410'd). */
function expireOffer(releaseCli) {
  if (phase.kind !== 'offer' && phase.kind !== 'remembering') return;
  const { doneEnvelope } = phase.data;
  phase = { kind: 'finished' };
  document.title = 'keytap: finished';
  $('offer').hidden = true;
  if (releaseCli && doneEnvelope) {
    post(doneEnvelope).catch(() => {});
  }
  const name = config.keyName;
  alertUser(
    'That machine has finished waiting, so this page can no longer set it up. Nothing was stored. To remember ',
    { code: name }, ' there, run ', { code: `keytap remember ${name}` }, ' in that terminal.'
  );
  $('alert').focus();
}

// ─── Offer flow ───

function humanDuration(secs) {
  return secs < 90 ? `about ${secs} seconds` : `about ${Math.round(secs / 60)} minutes`;
}

function setOfferButtonsDisabled(disabled) {
  for (const btn of [$('remember-btn'), $('done-btn')]) {
    btn.setAttribute('aria-disabled', disabled ? 'true' : 'false');
  }
}

function enterOffer(firstResult) {
  const name = config.keyName;
  render($('offer-body'),
    'That machine can keep ', { code: name }, ', so keytap stops prompting for it until ',
    { code: `keytap forget ${name}` }, '. Confirming takes one more passkey check.'
  );
  $('offer-hint').textContent =
    `This offer ends when that machine stops waiting, in ${humanDuration(config.windowSecs)}. Don’t remember stores nothing.`;
  setOfferButtonsDisabled(false);
  $('offer').hidden = false;
  say('Sent. Your CLI has the key.');
  $('offer-heading').focus();
  phase = {
    kind: 'offer',
    data: {
      firstResult,
      expiryAt: 0,
      pendingEnvelope: encryptEnvelope({ type: 'remember-pending' }),
      doneEnvelope: null,
    },
  };
  armExpiry();
  // The beacon cannot run async crypto inside pagehide, and the pending
  // probe should not make the user wait; its envelope was built above.
  encryptEnvelope({ type: 'done' }).then(envelope => {
    if (phase.kind === 'offer' || phase.kind === 'remembering') phase.data.doneEnvelope = envelope;
  }, () => {});
}

async function onRememberTap() {
  if (phase.kind !== 'offer') return;
  const data = phase.data;
  phase = { kind: 'remembering', step: 'probe', data };
  setOfferButtonsDisabled(true);

  // Liveness probe before any gesture is spent: a dead session becomes
  // guidance here, never a wasted Face ID.
  const probeStarted = performance.now();
  let resp;
  try {
    resp = await post(await data.pendingEnvelope, 4000);
  } catch {
    phase = { kind: 'offer', data };
    setOfferButtonsDisabled(false);
    alertUser("Couldn't reach the relay. Nothing was stored. Tap Remember on that machine to try again.");
    $('remember-btn').focus();
    return;
  }
  const probeMs = performance.now() - probeStarted;
  if (resp.status === 410) {
    expireOffer(false);
    return;
  }
  if (!resp.ok) {
    phase = { kind: 'offer', data };
    setOfferButtonsDisabled(false);
    alertUser("Couldn't reach the relay. Nothing was stored. Tap Remember on that machine to try again.");
    $('remember-btn').focus();
    return;
  }

  phase = { kind: 'remembering', step: 'ceremony', data };
  say('Confirming with your passkey…');
  document.title = 'keytap: approve';
  const ceremonyStarted = performance.now();
  let second;
  try {
    second = await runAssertion(data.firstResult.rawId);
  } catch (e) {
    phase = { kind: 'offer', data };
    setOfferButtonsDisabled(false);
    document.title = 'keytap: sent';
    if (isCancel(e) && performance.now() - ceremonyStarted < 200 && probeMs > 2000) {
      // The prompt never opened: the slow probe outlived the tap's
      // transient activation. Not a user decision.
      say('The passkey prompt didn’t open. Tap Remember on that machine to try again.');
    } else if (isCancel(e)) {
      say('Passkey check cancelled. The key was already sent; nothing was stored.');
    } else {
      console.error(e);
      alertUser(e.message);
    }
    $('remember-btn').focus();
    return;
  }

  // The sheet is pinned to the first credential, so a mismatch means a
  // broken authenticator UI; refuse locally, nothing leaves the page.
  if (encodeBase64URL(second.credential.rawId) !== data.firstResult.credentialIdB64
      || encodeBase64URL(second.prfFirst) !== data.firstResult.prfFirstB64) {
    phase = { kind: 'offer', data };
    setOfferButtonsDisabled(false);
    document.title = 'keytap: sent';
    alertUser('That approval used a different passkey, so nothing was sent. Try again with the passkey that just derived the key.');
    $('remember-btn').focus();
    return;
  }

  say('Encrypting and sending…');
  const envelope = await encryptEnvelope({
    type: 'assert-success',
    credentialId: data.firstResult.credentialIdB64,
    prfFirst: data.firstResult.prfFirstB64,
    remember: true,
  });
  phase = { kind: 'remember-posting', envelope };
  await postRemember(envelope);
}

async function postRemember(envelope) {
  let resp;
  try {
    resp = await post(envelope);
  } catch {
    phase = { kind: 'remember-retry', envelope };
    alertUser("Couldn't reach the relay. Nothing was stored. Tap Try again to resend.");
    const btn = $('remember-btn');
    btn.textContent = 'Try again';
    btn.setAttribute('aria-disabled', 'false');
    btn.focus();
    return;
  }
  phase = { kind: 'finished' };
  $('offer').hidden = true;
  const name = config.keyName;
  if (resp.status === 410) {
    document.title = 'keytap: finished';
    alertUser(
      'Your passkey check succeeded, but that machine had already finished waiting, so nothing was sent or stored. To remember ',
      { code: name }, ' there, run ', { code: `keytap remember ${name}` }, ' in that terminal.'
    );
    $('alert').focus();
    return;
  }
  document.title = 'keytap: remembered';
  setMarker('remembered');
  say('Remember request sent. The terminal on that machine confirms where the key was stored. You can close this page.');
  $('status').focus();
}

function onDoneTap() {
  if (phase.kind !== 'offer') return;
  const { doneEnvelope } = phase.data;
  phase = { kind: 'finished' };
  document.title = 'keytap: finished';
  $('offer').hidden = true;
  if (doneEnvelope) {
    // 410 just means the CLI already left; not an error.
    post(doneEnvelope).catch(() => {});
  }
  say('Done. You can close this page.');
  $('status').focus();
}

// Retry that resends the held remember envelope, never a new ceremony.
function onRememberButton() {
  if (phase.kind === 'remember-retry') {
    const { envelope } = phase;
    $('remember-btn').setAttribute('aria-disabled', 'true');
    phase = { kind: 'remember-posting', envelope };
    say('Encrypting and sending…');
    postRemember(envelope);
  } else {
    onRememberTap();
  }
}

// ─── First ceremony (assert) ───

function enterSent(firstResult) {
  document.title = 'keytap: sent';
  $('summary').hidden = true;
  $('explainer').hidden = true;
  $('details').hidden = true;
  $('start').remove();
  if (config.operation === 'register') {
    // No marker: reloading a spent register session has nothing to finish.
    $('title').textContent = 'Passkey created';
    say('Sent to your CLI. You can close this page.');
    phase = { kind: 'finished' };
    return;
  }
  $('title').textContent = 'Key sent';
  setMarker('sent');
  const name = config.keyName;
  if (config.windowSecs > 0) {
    enterOffer(firstResult);
  } else if (config.legacyRemember) {
    say(
      'Sent. You can close this page. To remember ', { code: name },
      ' on that machine, run ', { code: `keytap remember ${name}` }, ' there.'
    );
    phase = { kind: 'finished' };
  } else {
    say('Sent. You can close this page.');
    phase = { kind: 'finished' };
  }
}

async function postFirst(envelope, firstResult) {
  say('Encrypting and sending…');
  let resp;
  try {
    resp = await post(envelope);
  } catch {
    phase = firstResult
      ? { kind: 'ready', action: 'resend-assert', envelope, firstResult }
      : { kind: 'ready', action: 'resend-register', envelope };
    const btn = $('start');
    btn.textContent = 'Try again';
    btn.disabled = false;
    alertUser("Couldn't reach the relay. Nothing was sent. Tap Try again to resend.");
    return;
  }
  if (resp.status === 410) {
    phase = { kind: 'finished' };
    $('start').remove();
    alertUser('Your CLI stopped waiting. Run the command again and scan the fresh code.');
    return;
  }
  if (!resp.ok) {
    phase = firstResult
      ? { kind: 'ready', action: 'resend-assert', envelope, firstResult }
      : { kind: 'ready', action: 'resend-register', envelope };
    const btn = $('start');
    btn.textContent = 'Try again';
    btn.disabled = false;
    alertUser("Couldn't reach the relay. Nothing was sent. Tap Try again to resend.");
    return;
  }
  enterSent(firstResult);
}

async function runFirst() {
  const btn = $('start');
  phase = { kind: 'first-busy' };
  btn.disabled = true;
  document.title = 'keytap: approve';

  let envelope;
  let firstResult;
  try {
    if (config.operation === 'register') {
      say('Waiting for passkey creation…');
      const credential = await runRegister();
      envelope = await encryptEnvelope({
        type: 'register-success',
        credentialId: encodeBase64URL(credential.rawId),
      });
    } else {
      say('Waiting for passkey approval…');
      const { credential, prfFirst } = await runAssertion(null);
      firstResult = {
        rawId: credential.rawId,
        credentialIdB64: encodeBase64URL(credential.rawId),
        prfFirstB64: encodeBase64URL(prfFirst),
      };
      const payload = {
        type: 'assert-success',
        credentialId: firstResult.credentialIdB64,
        prfFirst: firstResult.prfFirstB64,
      };
      // Announce follow-up capability only to a CLI that lingers for it.
      if (config.windowSecs > 0) payload.follow = true;
      envelope = await encryptEnvelope(payload);
    }
  } catch (e) {
    phase = { kind: 'ready', action: 'run' };
    btn.disabled = false;
    const label = config.operation === 'register' ? 'Create passkey' : 'Approve request';
    btn.textContent = label;
    if (isCancel(e)) {
      say(`The passkey prompt was cancelled or didn’t open. Nothing was sent. Tap ${label} to try again.`);
    } else {
      console.error(e);
      alertUser(e.message);
    }
    return;
  }

  await postFirst(envelope, firstResult);
}

// ─── Terminal states reached without a live session ───

function renderFinished(marker) {
  $('title').textContent = 'Key sent';
  document.title = 'keytap: finished';
  $('summary').hidden = true;
  $('explainer').hidden = true;
  $('details').hidden = true;
  $('start')?.remove();
  $('offer').hidden = true;
  phase = { kind: 'finished' };
  if (marker && marker.state === 'remembered') {
    document.title = 'keytap: remembered';
    say('Remember request sent. The terminal on that machine confirms where the key was stored. You can close this page.');
  } else {
    const name = marker?.name || 'default';
    say(
      'Finished on this page. To remember ', { code: name },
      ' on that machine, run ', { code: `keytap remember ${name}` }, ' there.'
    );
  }
  $('status').focus();
}

// ─── Lifecycle ───

window.addEventListener('pagehide', () => {
  // Once the second ceremony starts, silence: a done racing the remember
  // follow-up could discard an explicitly confirmed choice.
  const canRelease = phase.kind === 'offer'
    || (phase.kind === 'remembering' && phase.step === 'probe');
  if (canRelease && phase.data.doneEnvelope) {
    const { doneEnvelope } = phase.data;
    phase = { kind: 'released' };
    // A plain string rides as text/plain, the only content type beacons
    // can send cross-origin without a preflight.
    navigator.sendBeacon(`${RELAY_URL}/relay/${sessionId}`, doneEnvelope);
  }
});

window.addEventListener('pageshow', e => {
  if (e.persisted && phase.kind === 'released') {
    renderFinished(getMarker(sessionId));
  }
});

document.addEventListener('visibilitychange', () => {
  if (!document.hidden && (phase.kind === 'offer' || phase.kind === 'remembering')) scheduleExpiryCheck();
});

// ─── Entry ───

async function main() {
  let marker = null;
  try {
    config = await fetchConfig();
  } catch (e) {
    phase = { kind: 'finished' };
    $('start').remove();
    $('title').textContent = 'keytap';
    $('explainer').hidden = true;
    $('details').hidden = true;
    if (e && e.kind === 'gone') {
      sessionId = e.sid;
      marker = getMarker(e.sid);
      if (marker) {
        renderFinished(marker);
        return;
      }
      alertUser('This code was already used or has expired. Run the keytap command again for a fresh one.');
    } else if (e && e.kind === 'network') {
      alertUser("Couldn't reach the relay. Check the connection and reload this page.");
    } else {
      alertUser('No session in URL.');
    }
    return;
  }
  sessionId = config.sessionId;

  const isRegister = config.operation === 'register';
  $('title').textContent = isRegister ? 'Create your keytap passkey' : 'Approve this key request';
  if (isRegister) {
    $('summary').textContent = 'Create the passkey once, then keytap can recover the same keys anywhere.';
    $('explainer').textContent = 'No account is needed. Your passkey stays in your password manager.';
  } else {
    render($('summary'), 'Your CLI requested key: ', { code: config.keyName });
  }

  $('remember-btn').addEventListener('click', onRememberButton);
  $('done-btn').addEventListener('click', onDoneTap);

  const btn = $('start');
  btn.textContent = isRegister ? 'Create passkey' : 'Approve request';
  btn.addEventListener('click', () => {
    if (phase.kind === 'ready' && phase.action === 'resend-register') {
      const { envelope } = phase;
      phase = { kind: 'first-busy' };
      btn.disabled = true;
      postFirst(envelope, null);
    } else if (phase.kind === 'ready' && phase.action === 'resend-assert') {
      const { envelope, firstResult } = phase;
      phase = { kind: 'first-busy' };
      btn.disabled = true;
      postFirst(envelope, firstResult);
    } else if (phase.kind === 'ready' && phase.action === 'run') {
      runFirst();
    }
  });

  if (isRegister) {
    say('Ready.');
    phase = { kind: 'ready', action: 'run' };
    btn.disabled = false;
  } else {
    // Opening the page from a QR scan provides transient user activation;
    // the passkey prompt appears without another tap.
    runFirst();
  }
}

main();
