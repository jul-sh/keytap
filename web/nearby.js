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
/** First ceremony result: rawId (ArrayBuffer) plus its encodings. */
let firstResult = null;
/** Held envelopes: retries re-POST these, never re-run a ceremony. */
let firstEnvelope = null;
let rememberEnvelope = null;
/** Precomputed at offer entry; pagehide handlers cannot run async crypto. */
let doneEnvelope = null;
let pendingEnvelopePromise = null;

let offerShown = false;
let ceremony2Started = false;
let followUpInitiated = false;
/** A done was sent (tap, beacon, or expiry) or the session is over. */
let released = false;
/** A POST or ceremony is in flight; the expiry timer waits it out. */
let busy = false;
let finished = false;
let expiryAt = 0;
let expiryTimer = 0;
/** What #start does when tapped: rerun the ceremony or resend the held
 * first envelope. */
let startMode = 'run';

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
  expiryAt = Date.now() + Math.max(config.windowSecs - 10, 5) * 1000;
  scheduleExpiryCheck();
}

function scheduleExpiryCheck() {
  clearTimeout(expiryTimer);
  expiryTimer = setTimeout(checkExpiry, Math.max(expiryAt - Date.now(), 0) + 20);
}

function checkExpiry() {
  if (finished || followUpInitiated) return;
  if (busy) {
    // Never expire mid-ceremony or mid-POST; look again shortly.
    expiryTimer = setTimeout(checkExpiry, 1000);
    return;
  }
  if (Date.now() >= expiryAt) {
    expireOffer(true);
  } else {
    scheduleExpiryCheck();
  }
}

/** @param {boolean} releaseCli post the done envelope so the terminal frees
 * up as this guidance renders (skipped when the CLI already 410'd). */
function expireOffer(releaseCli) {
  finished = true;
  document.title = 'keytap: finished';
  $('offer').hidden = true;
  if (releaseCli && doneEnvelope && !released) {
    released = true;
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

function offerButtonsDisabled() {
  return $('remember-btn').getAttribute('aria-disabled') === 'true';
}

function enterOffer() {
  offerShown = true;
  const name = config.keyName;
  render($('offer-body'),
    'That machine can keep ', { code: name }, ', so keytap stops prompting for it until ',
    { code: `keytap forget ${name}` }, '. Confirming takes one more passkey check.'
  );
  $('offer-hint').textContent =
    `This offer ends when that machine stops waiting, in ${humanDuration(config.windowSecs)}. Done stores nothing.`;
  setOfferButtonsDisabled(false);
  $('offer').hidden = false;
  say('Sent. Your CLI has the key.');
  $('offer-heading').focus();
  armExpiry();
  // The beacon cannot run async crypto inside pagehide, and the pending
  // probe should not make the user wait; both envelopes are built now.
  pendingEnvelopePromise = encryptEnvelope({ type: 'remember-pending' });
  encryptEnvelope({ type: 'done' }).then(envelope => { doneEnvelope = envelope; }, () => {});
}

async function onRememberTap() {
  if (offerButtonsDisabled() || busy) return;
  busy = true;
  setOfferButtonsDisabled(true);

  // Liveness probe before any gesture is spent: a dead session becomes
  // guidance here, never a wasted Face ID.
  const probeStarted = performance.now();
  let resp;
  try {
    resp = await post(await pendingEnvelopePromise, 4000);
  } catch {
    busy = false;
    setOfferButtonsDisabled(false);
    alertUser("Couldn't reach the relay. Nothing was stored. Tap Remember on that machine to try again.");
    $('remember-btn').focus();
    return;
  }
  const probeMs = performance.now() - probeStarted;
  if (resp.status === 410) {
    busy = false;
    expireOffer(false);
    return;
  }
  if (!resp.ok) {
    busy = false;
    setOfferButtonsDisabled(false);
    alertUser("Couldn't reach the relay. Nothing was stored. Tap Remember on that machine to try again.");
    $('remember-btn').focus();
    return;
  }

  ceremony2Started = true;
  say('Confirming with your passkey…');
  document.title = 'keytap: approve';
  const ceremonyStarted = performance.now();
  let second;
  try {
    second = await runAssertion(firstResult.rawId);
  } catch (e) {
    busy = false;
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
  if (encodeBase64URL(second.credential.rawId) !== firstResult.credentialIdB64
      || encodeBase64URL(second.prfFirst) !== firstResult.prfFirstB64) {
    busy = false;
    setOfferButtonsDisabled(false);
    document.title = 'keytap: sent';
    alertUser('That approval used a different passkey, so nothing was sent. Try again with the passkey that just derived the key.');
    $('remember-btn').focus();
    return;
  }

  say('Encrypting and sending…');
  rememberEnvelope = await encryptEnvelope({
    type: 'assert-success',
    credentialId: firstResult.credentialIdB64,
    prfFirst: firstResult.prfFirstB64,
    remember: true,
  });
  // From here on the pagehide beacon stays silent: a done racing this
  // follow-up could drop an explicitly confirmed remember.
  followUpInitiated = true;
  await postRemember();
}

async function postRemember() {
  let resp;
  try {
    resp = await post(rememberEnvelope);
  } catch {
    busy = false;
    alertUser("Couldn't reach the relay. Nothing was stored. Tap Try again to resend.");
    const btn = $('remember-btn');
    btn.textContent = 'Try again';
    btn.setAttribute('aria-disabled', 'false');
    btn.focus();
    return;
  }
  busy = false;
  finished = true;
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
  if (offerButtonsDisabled() || busy) return;
  finished = true;
  document.title = 'keytap: finished';
  $('offer').hidden = true;
  if (doneEnvelope && !released) {
    released = true;
    // 410 just means the CLI already left; not an error.
    post(doneEnvelope).catch(() => {});
  }
  say('Done. You can close this page.');
  $('status').focus();
}

// Retry that resends the held remember envelope, never a new ceremony.
function onRememberButton() {
  if (followUpInitiated && rememberEnvelope) {
    if ($('remember-btn').getAttribute('aria-disabled') === 'true') return;
    $('remember-btn').setAttribute('aria-disabled', 'true');
    busy = true;
    say('Encrypting and sending…');
    postRemember();
  } else {
    onRememberTap();
  }
}

// ─── First ceremony (assert) ───

function enterSent() {
  document.title = 'keytap: sent';
  $('explainer').hidden = true;
  $('details').hidden = true;
  $('start').remove();
  if (config.operation === 'register') {
    // No marker: reloading a spent register session has nothing to finish.
    say('Sent. You can close this page.');
    return;
  }
  $('title').textContent = 'Key sent';
  setMarker('sent');
  const name = config.keyName;
  if (config.windowSecs > 0) {
    enterOffer();
  } else if (config.legacyRemember) {
    say(
      'Sent. You can close this page. To remember ', { code: name },
      ' on that machine, run ', { code: `keytap remember ${name}` }, ' there.'
    );
  } else {
    say('Sent. You can close this page.');
  }
}

async function postFirst() {
  say('Encrypting and sending…');
  let resp;
  try {
    resp = await post(firstEnvelope);
  } catch {
    startMode = 'resend';
    const btn = $('start');
    btn.textContent = 'Try again';
    btn.disabled = false;
    alertUser("Couldn't reach the relay. Nothing was sent. Tap Try again to resend.");
    return;
  }
  if (resp.status === 410) {
    $('start').remove();
    alertUser('Your CLI stopped waiting. Run the command again and scan the fresh code.');
    return;
  }
  if (!resp.ok) {
    startMode = 'resend';
    const btn = $('start');
    btn.textContent = 'Try again';
    btn.disabled = false;
    alertUser("Couldn't reach the relay. Nothing was sent. Tap Try again to resend.");
    return;
  }
  enterSent();
}

async function runFirst() {
  const btn = $('start');
  btn.disabled = true;
  document.title = 'keytap: approve';

  try {
    if (config.operation === 'register') {
      say('Waiting for passkey creation…');
      const credential = await runRegister();
      firstEnvelope = await encryptEnvelope({
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
      firstEnvelope = await encryptEnvelope(payload);
    }
  } catch (e) {
    btn.disabled = false;
    const label = config.operation === 'register' ? 'Create passkey' : 'Authenticate';
    btn.textContent = label;
    if (isCancel(e)) {
      say(`The passkey prompt was cancelled or didn’t open. Nothing was sent. Tap ${label} to try again.`);
    } else {
      console.error(e);
      alertUser(e.message);
    }
    return;
  }

  await postFirst();
}

// ─── Terminal states reached without a live session ───

function renderFinished(marker) {
  $('title').textContent = 'Key sent';
  document.title = 'keytap: finished';
  $('explainer').hidden = true;
  $('details').hidden = true;
  $('start')?.remove();
  $('offer').hidden = true;
  finished = true;
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
  // Only from a live, undecided offer. Once a second ceremony started or
  // the follow-up is on the wire, silence: the CLI's own window bounds it.
  if (offerShown && !ceremony2Started && !followUpInitiated && !released && doneEnvelope) {
    released = true;
    // A plain string rides as text/plain, the only content type beacons
    // can send cross-origin without a preflight.
    navigator.sendBeacon(`${RELAY_URL}/relay/${sessionId}`, doneEnvelope);
  }
});

window.addEventListener('pageshow', e => {
  if (e.persisted && released && !finished) {
    renderFinished(getMarker(sessionId));
  }
});

document.addEventListener('visibilitychange', () => {
  if (!document.hidden && offerShown && !finished) scheduleExpiryCheck();
});

// ─── Entry ───

async function main() {
  let marker = null;
  try {
    config = await fetchConfig();
  } catch (e) {
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
  $('title').textContent = isRegister ? 'Create the keytap passkey' : 'Approve on this device';
  if (isRegister) {
    $('summary').textContent = 'Create the passkey once, then keytap can recover the same keys anywhere.';
  } else {
    render($('summary'), 'Approve to derive key: ', { code: config.keyName });
  }

  $('remember-btn').addEventListener('click', onRememberButton);
  $('done-btn').addEventListener('click', onDoneTap);

  const btn = $('start');
  btn.textContent = isRegister ? 'Create passkey' : 'Authenticate';
  btn.addEventListener('click', () => {
    if (startMode === 'resend') {
      btn.disabled = true;
      postFirst();
    } else {
      runFirst();
    }
  });

  if (isRegister) {
    say('Ready.');
    btn.disabled = false;
  } else {
    // Opening the page from a QR scan provides transient user activation;
    // the passkey prompt appears without another tap.
    runFirst();
  }
}

main();
