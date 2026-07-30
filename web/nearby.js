import {
  CLOUDFLARE_STUN_ONLY,
  ProtocolError,
  TURN_IDENTITY_PRF_SALT,
  createCliOfferVerifier,
  createNearbyIdentityProof,
  createNearbySessionBinding,
  createSasCommitment,
  createSasContext,
  createSasDigest,
  createTurnPasskeyAuthorizationProof,
  decodeBase64URL,
  encodeBase64URL,
  filterCloudflareIceServers,
  parseSasWordList,
  sasPhrase,
  verifySasCommitment,
} from './nearby-protocol.js';

const SIGNAL_ORIGIN = 'https://keytap-signal.julsh.workers.dev';
const SIGNAL_OPEN_TIMEOUT_MS = 30_000;
const SIGNAL_TIMEOUT_MS = 120_000;
const ICE_GATHER_TIMEOUT_MS = 45_000;
const DATA_CONNECT_TIMEOUT_MS = 60_000;
const DATA_MESSAGE_TIMEOUT_MS = 120_000;
const MAX_SIGNAL_BYTES = 128 * 1024;
const MAX_DATA_BYTES = 16 * 1024;
const MAX_TURN_RESPONSE_BYTES = 64 * 1024;
const MAX_TURN_ERROR_BYTES = 1024;
const MAX_TURN_CHALLENGE_BYTES = 2048;
const MAX_SAS_WORD_LIST_BYTES = 32 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

let identityWasmPromise;

async function deriveEd25519PublicKey(identitySeed) {
  if (!(identitySeed instanceof Uint8Array) || identitySeed.length !== 32) {
    throw new ProtocolError('invalid identity PRF output');
  }
  identityWasmPromise ??= import('./pkg/keytap_web.js').then(async module => {
    await module.default();
    return module;
  });
  const wasm = await identityWasmPromise;
  const publicKey = new Uint8Array(wasm.ed25519PublicKey(identitySeed));
  if (publicKey.length !== 32) {
    throw new ProtocolError('browser returned an invalid Ed25519 identity');
  }
  return publicKey;
}

const $ = id => document.getElementById(id);

/** @param {HTMLElement} element */
function render(element, ...parts) {
  element.textContent = '';
  for (const part of parts) {
    if (typeof part === 'string') {
      element.append(part);
    } else {
      const code = document.createElement('code');
      code.textContent = part.code;
      element.append(code);
    }
  }
}

function say(...parts) {
  $('alert').textContent = '';
  render($('status'), ...parts);
}

function alertUser(...parts) {
  $('status').textContent = '';
  render($('alert'), ...parts);
}

/**
 * Each phase owns exactly the data valid in that state. In particular, an
 * assertion result exists only after an assertion ceremony. A storage choice
 * exists only before that ceremony and carries no key material.
 *
 * @typedef {
 *   {kind: 'boot'} |
 *   {kind: 'connecting-direct', data: ConnectingData} |
 *   {kind: 'relay-consent', data: RelayConsentData} |
 *   {kind: 'relay-authorizing', data: ConnectingData} |
 *   {kind: 'connecting-relay', data: ConnectingData} |
 *   {kind: 'awaiting-request', session: DataSession} |
 *   {kind: 'disposition-choice', data: ChoiceData} |
 *   {kind: 'first-busy', data: FirstBusyData} |
 *   {kind: 'pairing-ceremony', data: PairingCeremonyData} |
 *   {kind: 'registration-ack', session: DataSession} |
 *   {kind: 'assertion-ack', data: AssertionData} |
 *   {kind: 'completed-elsewhere'} |
 *   {kind: 'finished'} |
 *   {kind: 'failed'} |
 *   {kind: 'expired'}
 * } Phase
 * @typedef {{controller: AbortController}} ConnectingData
 * @typedef {{connection: ConnectingData, proceed: () => void}} RelayConsentData
 * @typedef {{session: DataSession, request: AssertRequest, sessionBinding: Uint8Array}} PinnedData
 * @typedef {PinnedData & {controller: AbortController, disposition: Disposition}} FirstBusyData
 * @typedef {{session: DataSession, request: AssertRequest, disposition: Disposition}} AssertionData
 * @typedef {{session: DataSession, binding: {kind: 'bootstrap-sas', digest: Uint8Array}}} PairingBaseData
 * @typedef {(PairingBaseData & {kind: 'registration', request: RegisterRequest, controller: AbortController}) | (PairingBaseData & {kind: 'assertion', request: AssertRequest, disposition: Disposition, controller: AbortController})} PairingCeremonyData
 * @typedef {(PinnedData & {kind: 'pinned'}) | (PairingBaseData & {kind: 'pairing', request: AssertRequest})} ChoiceData
 * @typedef {{kind: 'register', challenge: Uint8Array, prfSalt: Uint8Array, userId: Uint8Array, userName: string}} RegisterRequest
 * @typedef {{kind: 'assert', challenge: Uint8Array, prfSalt: Uint8Array, identitySalt: Uint8Array, identity: IdentityMode, keyName: string, storage: StoragePolicy}} AssertRequest
 * @typedef {{kind: 'pairing-any'} | {kind: 'pairing-credential', credentialId: Uint8Array} | {kind: 'pinned', credentialId: Uint8Array}} IdentityMode
 * @typedef {'choose' | 'remember'} StoragePolicy
 * @typedef {'once' | 'remember'} Disposition
 * @typedef {{send: (message: object) => void, next: (timeoutMs?: number) => Promise<object>, close: () => void}} DataSession
 * @typedef {{kind: 'turn-passkey-challenge', challenge: Uint8Array, expiresAt: number}} TurnPasskeyChallenge
 * @typedef {string} TurnCapability Canonical base64url Ed25519 signature used as a short-lived bearer.
 * @typedef {{type: 'turn-authorized', capability: TurnCapability} | {type: 'turn-unavailable', reason: 'not-allowlisted' | 'cancelled' | 'passkey-unavailable' | 'provider-unavailable'}} TurnRetryControl
 * @typedef {{capability: TurnCapability, iceServers: RTCIceServer[]}} AuthorizedRelay
 * @typedef {{kind: 'connected', session: DataSession, sessionBinding: Uint8Array} | {kind: 'turn-required'}} ConnectionAttemptOutcome
 * @typedef {{sequence: 0 | 1, iceServers: RTCIceServer[], turnRequiredPolicy: 'accept' | 'ignore-stale'}} ConnectionAttemptSpec
 */

/** @type {Phase} */
let phase = { kind: 'boot' };

class AsyncQueue {
  constructor() {
    this.items = [];
    this.waiters = [];
    this.failure = null;
  }

  push(value) {
    if (this.failure) return;
    const waiter = this.waiters.shift();
    if (waiter) {
      clearTimeout(waiter.timer);
      waiter.resolve(value);
    } else {
      this.items.push(value);
    }
  }

  fail(error) {
    if (this.failure) return;
    this.failure = error instanceof Error ? error : new Error(String(error));
    for (const waiter of this.waiters.splice(0)) {
      clearTimeout(waiter.timer);
      waiter.reject(this.failure);
    }
  }

  next(timeoutMs) {
    if (this.items.length > 0) return Promise.resolve(this.items.shift());
    if (this.failure) return Promise.reject(this.failure);
    return new Promise((resolve, reject) => {
      const waiter = { resolve, reject, timer: 0 };
      if (timeoutMs) {
        waiter.timer = setTimeout(() => {
          const index = this.waiters.indexOf(waiter);
          if (index !== -1) this.waiters.splice(index, 1);
          reject(new ProtocolError('timed out waiting for the other device'));
        }, timeoutMs);
      }
      this.waiters.push(waiter);
    });
  }
}

function abortFailure(signal) {
  return signal.reason instanceof Error
    ? signal.reason
    : new DOMException('The operation was aborted.', 'AbortError');
}

function throwIfAborted(signal) {
  if (signal?.aborted) throw abortFailure(signal);
}

function abortable(promise, signal) {
  if (!signal) return promise;
  try {
    throwIfAborted(signal);
  } catch (error) {
    return Promise.reject(error);
  }
  return new Promise((resolve, reject) => {
    const onAbort = () => reject(abortFailure(signal));
    signal.addEventListener('abort', onAbort, { once: true });
    Promise.resolve(promise).then(
      value => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      error => {
        signal.removeEventListener('abort', onAbort);
        reject(error);
      },
    );
  });
}

function abortAfter(ms, parentSignal) {
  const timeoutSignal = typeof AbortSignal.timeout === 'function'
    ? AbortSignal.timeout(ms)
    : (() => {
      const controller = new AbortController();
      setTimeout(() => controller.abort(), ms);
      return controller.signal;
    })();
  if (!parentSignal) return timeoutSignal;
  if (typeof AbortSignal.any === 'function') {
    return AbortSignal.any([parentSignal, timeoutSignal]);
  }
  const controller = new AbortController();
  const forwardAbort = signal => {
    if (!controller.signal.aborted) controller.abort(signal.reason);
  };
  parentSignal.addEventListener('abort', () => forwardAbort(parentSignal), { once: true });
  timeoutSignal.addEventListener('abort', () => forwardAbort(timeoutSignal), { once: true });
  if (parentSignal.aborted) forwardAbort(parentSignal);
  return controller.signal;
}

function takeCliPublicKeyFromFragment() {
  const hash = location.hash.startsWith('#') ? location.hash.slice(1) : '';
  const params = new URLSearchParams(hash);
  const values = params.getAll('key');
  // Fragments are never sent in HTTP requests. Remove this one immediately so
  // it also stays out of screenshots, copied URLs, history, and crash reports.
  history.replaceState(null, '', location.pathname + location.search);
  if (values.length !== 1 || [...params.keys()].some(key => key !== 'key')) {
    throw new ProtocolError('No unambiguous nearby CLI public key in URL.');
  }
  let publicKey;
  try {
    publicKey = decodeBase64URL(values[0]);
  } catch {
    throw new ProtocolError('Invalid nearby CLI public key.');
  }
  if (publicKey.length !== 32) throw new ProtocolError('Invalid nearby CLI public key.');
  return publicKey;
}

function signalUrl(rendezvousId) {
  const url = new URL(SIGNAL_ORIGIN);
  url.protocol = 'wss:';
  url.pathname = `/signal/${encodeURIComponent(rendezvousId)}`;
  url.search = 'role=approver';
  return url.href;
}

export class CompletedElsewhereError extends ProtocolError {
  constructor() {
    super('approval completed on the Mac');
    this.name = 'CompletedElsewhereError';
  }
}

export async function openSignalSocket(rendezvousId, connection) {
  const cancellation = connection.controller.signal;
  throwIfAborted(cancellation);
  const socket = new WebSocket(signalUrl(rendezvousId));
  const incoming = new AsyncQueue();
  let ignoreSocketFailure = false;
  const failUnexpectedly = error => {
    incoming.fail(error);
    if (!ignoreSocketFailure && !cancellation.aborted) {
      connection.controller.abort(error);
    }
  };
  socket.addEventListener('message', event => {
    if (typeof event.data !== 'string' || encoder.encode(event.data).length > MAX_SIGNAL_BYTES) {
      failUnexpectedly(new ProtocolError('invalid signaling message'));
      return;
    }
    try {
      const message = JSON.parse(event.data);
      if (!message || typeof message !== 'object' || Array.isArray(message)) {
        throw new ProtocolError('invalid signaling message');
      }
      if (message.type === 'completed-elsewhere') {
        if (!hasExactKeys(message, ['type'])) {
          throw new ProtocolError('invalid completed-elsewhere signaling message');
        }
        const completion = new CompletedElsewhereError();
        incoming.fail(completion);
        if (!cancellation.aborted) connection.controller.abort(completion);
        return;
      }
      incoming.push(message);
    } catch {
      failUnexpectedly(new ProtocolError('invalid signaling message'));
    }
  });
  socket.addEventListener('close', () => {
    failUnexpectedly(new ProtocolError('signaling connection closed'));
  });
  socket.addEventListener('error', () => {
    failUnexpectedly(new ProtocolError('signaling connection failed'));
  });

  try {
    await abortable(new Promise((resolve, reject) => {
      let settled = false;
      const fail = error => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        reject(error);
      };
      const timer = setTimeout(() => {
        fail(new ProtocolError('timed out reaching signaling'));
        socket.close();
      }, SIGNAL_OPEN_TIMEOUT_MS);
      socket.addEventListener('open', () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve();
      }, { once: true });
      socket.addEventListener('error', () => fail(new ProtocolError('could not reach signaling')), { once: true });
      socket.addEventListener('close', () => fail(new ProtocolError('signaling connection closed')), { once: true });
    }), cancellation);
  } catch (error) {
    if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) socket.close();
    throw error;
  }

  const closeOnAbort = () => {
    incoming.fail(abortFailure(cancellation));
    if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) socket.close();
  };
  cancellation.addEventListener('abort', closeOnAbort, { once: true });

  return {
    next: timeoutMs => incoming.next(timeoutMs),
    send(message) {
      if (socket.readyState !== WebSocket.OPEN) throw new ProtocolError('signaling connection closed');
      const encoded = JSON.stringify(message);
      if (encoder.encode(encoded).length > MAX_SIGNAL_BYTES) throw new ProtocolError('signaling message is too large');
      socket.send(encoded);
    },
    connectionEstablished() {
      ignoreSocketFailure = true;
    },
    close() {
      ignoreSocketFailure = true;
      cancellation.removeEventListener('abort', closeOnAbort);
      if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING) socket.close();
    },
  };
}

async function waitForPeer(signal) {
  for (;;) {
    const message = await signal.next(SIGNAL_TIMEOUT_MS);
    if (message.type === 'peer-ready') return;
    if (message.type === 'error') {
      throw new ProtocolError(typeof message.message === 'string' ? message.message : 'signaling failed');
    }
    throw new ProtocolError('unexpected signaling state');
  }
}

function isExactTurnRequired(message) {
  return hasExactKeys(message, ['type']) && message.type === 'turn-required';
}

export async function waitForAttemptSignal(signal, turnRequiredPolicy) {
  if (turnRequiredPolicy !== 'accept' && turnRequiredPolicy !== 'ignore-stale') {
    throw new ProtocolError('invalid TURN retry signaling policy');
  }
  for (;;) {
    const message = await signal.next(SIGNAL_TIMEOUT_MS);
    if (message.type === 'peer-ready') continue;
    if (message.type === 'error') {
      throw new ProtocolError(typeof message.message === 'string' ? message.message : 'signaling failed');
    }
    if (isExactTurnRequired(message)) {
      switch (turnRequiredPolicy) {
        case 'accept':
          return { kind: 'turn-required' };
        case 'ignore-stale':
          continue;
      }
    }
    return { kind: 'offer', envelope: message };
  }
}

function isTurnNotAllowlistedPayload(payload) {
  return payload
    && typeof payload === 'object'
    && !Array.isArray(payload)
    && Object.keys(payload).length === 1
    && payload.kind === 'turn-not-allowlisted';
}

function hasExactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return keys.length === sortedExpected.length
    && keys.every((key, index) => key === sortedExpected[index]);
}

function parseTurnPasskeyChallenge(payload) {
  if (!hasExactKeys(payload, ['kind', 'challenge', 'expiresAt'])
      || payload.kind !== 'turn-passkey-challenge'
      || !Number.isSafeInteger(payload.expiresAt) || payload.expiresAt <= Date.now()) {
    throw new ProtocolError('TURN service returned an invalid passkey challenge');
  }
  const challenge = decodeBase64URL(payload.challenge);
  if (challenge.length !== 32) {
    throw new ProtocolError('TURN service returned an invalid passkey challenge');
  }
  return {
    kind: 'turn-passkey-challenge',
    challenge,
    expiresAt: payload.expiresAt,
  };
}

function exactTurnAuthorizationResponse(payload, kind) {
  return hasExactKeys(payload, ['kind']) && payload.kind === kind;
}

export class TurnPasskeyNotAllowlistedError extends ProtocolError {
  constructor() {
    super('the approved passkey identity is not allowlisted for TURN');
    this.name = 'TurnPasskeyNotAllowlistedError';
  }
}

export class TurnPasskeyCancelledError extends ProtocolError {
  constructor(cause) {
    super('TURN passkey authorization was cancelled');
    this.name = 'TurnPasskeyCancelledError';
    this.cause = cause;
  }
}

export class TurnPasskeyUnavailableError extends ProtocolError {
  constructor(message = 'this browser could not create the passkey identity proof') {
    super(message);
    this.name = 'TurnPasskeyUnavailableError';
  }
}

export class TurnProviderUnavailableError extends ProtocolError {
  constructor(message = 'TURN relay authorization is unavailable') {
    super(message);
    this.name = 'TurnProviderUnavailableError';
  }
}

/**
 * @param {unknown} value
 * @returns {TurnCapability}
 */
function requireTurnCapability(value) {
  try {
    const bytes = decodeBase64URL(value);
    if (bytes.length !== 64) throw new ProtocolError('invalid TURN capability');
    return value;
  } catch {
    throw new TurnPasskeyUnavailableError('the browser created an invalid TURN identity capability');
  }
}

/** @returns {Promise<TurnPasskeyChallenge>} */
export async function fetchTurnPasskeyChallenge(rendezvousId, cancellation) {
  throwIfAborted(cancellation);
  const url = `${SIGNAL_ORIGIN}/signal/${encodeURIComponent(rendezvousId)}/turn/challenge`;
  let response;
  try {
    response = await fetch(url, {
      method: 'POST',
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      headers: { Accept: 'application/json' },
      signal: abortAfter(SIGNAL_OPEN_TIMEOUT_MS, cancellation),
    });
  } catch {
    throwIfAborted(cancellation);
    throw new TurnProviderUnavailableError('could not request a TURN passkey challenge');
  }
  if (!response.ok) {
    throw new TurnProviderUnavailableError('TURN passkey challenge service is unavailable');
  }
  try {
    return parseTurnPasskeyChallenge(
      await readBoundedJson(response, MAX_TURN_CHALLENGE_BYTES),
    );
  } catch (error) {
    throwIfAborted(cancellation);
    if (error instanceof TurnProviderUnavailableError) throw error;
    throw new TurnProviderUnavailableError('TURN service returned an invalid passkey challenge');
  }
}

async function createTurnPasskeyProof(
  rendezvousId,
  challenge,
  cancellation,
  publicKeyDeriver,
) {
  let credential;
  try {
    credential = await navigator.credentials.get({
      signal: cancellation,
      publicKey: {
        challenge: challenge.challenge,
        rpId: 'keytap.jul.sh',
        userVerification: 'required',
        timeout: 120_000,
        extensions: {
          prf: { eval: { first: TURN_IDENTITY_PRF_SALT } },
        },
      },
    });
  } catch (error) {
    throwIfAborted(cancellation);
    if (isCancel(error)) throw new TurnPasskeyCancelledError(error);
    throw new TurnPasskeyUnavailableError('the passkey could not create a TURN identity proof');
  }
  const prfFirst = credential?.getClientExtensionResults()?.prf?.results?.first;
  if (!credential?.rawId || !prfFirst) {
    throw new TurnPasskeyUnavailableError('the passkey did not return its nearby identity');
  }
  const credentialId = new Uint8Array(credential.rawId);
  if (credentialId.length < 1 || credentialId.length > 1024) {
    throw new TurnPasskeyUnavailableError('the passkey returned an invalid credential ID');
  }
  const identitySeed = new Uint8Array(prfFirst);
  try {
    let proof;
    try {
      proof = await createTurnPasskeyAuthorizationProof({
        rendezvousId,
        challenge: challenge.challenge,
        expiresAt: challenge.expiresAt,
        credentialId,
      }, identitySeed, publicKeyDeriver);
    } catch {
      throwIfAborted(cancellation);
      throw new TurnPasskeyUnavailableError('this browser could not create the TURN identity proof');
    }
    return {
      kind: 'turn-passkey-proof',
      challenge: encodeBase64URL(challenge.challenge),
      expiresAt: challenge.expiresAt,
      credentialId: encodeBase64URL(credentialId),
      publicKey: encodeBase64URL(proof.publicKey),
      signature: encodeBase64URL(proof.signature),
    };
  } finally {
    identitySeed.fill(0);
  }
}

async function submitTurnPasskeyProof(rendezvousId, proof, cancellation) {
  throwIfAborted(cancellation);
  const url = `${SIGNAL_ORIGIN}/signal/${encodeURIComponent(rendezvousId)}/turn/authorize`;
  let response;
  try {
    response = await fetch(url, {
      method: 'POST',
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
      body: JSON.stringify(proof),
      signal: abortAfter(SIGNAL_OPEN_TIMEOUT_MS, cancellation),
    });
  } catch {
    throwIfAborted(cancellation);
    throw new TurnProviderUnavailableError('could not submit TURN passkey authorization');
  }

  let payload;
  try {
    payload = await readBoundedJson(response, MAX_TURN_ERROR_BYTES);
  } catch {
    throwIfAborted(cancellation);
    throw new TurnProviderUnavailableError('TURN authorization returned an invalid response');
  }
  if (response.status === 403
      && exactTurnAuthorizationResponse(payload, 'turn-not-allowlisted')) {
    throw new TurnPasskeyNotAllowlistedError();
  }
  if (response.ok && exactTurnAuthorizationResponse(payload, 'turn-authorized')) return;
  throw new TurnProviderUnavailableError('TURN authorization service is unavailable');
}

/** @returns {Promise<TurnCapability>} */
export async function authorizeTurnWithPasskey(
  rendezvousId,
  challenge,
  cancellation,
  publicKeyDeriver = deriveEd25519PublicKey,
) {
  let proof;
  try {
    proof = await createTurnPasskeyProof(
      rendezvousId,
      challenge,
      cancellation,
      publicKeyDeriver,
    );
  } catch (error) {
    throwIfAborted(cancellation);
    if (error instanceof TurnPasskeyCancelledError
        || error instanceof TurnPasskeyUnavailableError
        || error instanceof TurnProviderUnavailableError) {
      throw error;
    }
    throw new TurnPasskeyUnavailableError('the passkey could not authorize TURN relay access');
  }
  await submitTurnPasskeyProof(rendezvousId, proof, cancellation);
  return requireTurnCapability(proof.signature);
}

/**
 * @param {string} rendezvousId
 * @param {TurnCapability} capability
 * @param {AbortSignal} cancellation
 * @returns {Promise<RTCIceServer[]>}
 */
export async function fetchTurnIceServers(rendezvousId, capability, cancellation) {
  throwIfAborted(cancellation);
  const checkedCapability = requireTurnCapability(capability);
  const url = `${SIGNAL_ORIGIN}/signal/${encodeURIComponent(rendezvousId)}/turn`;
  let response;
  try {
    response = await fetch(url, {
      cache: 'no-store',
      credentials: 'omit',
      redirect: 'error',
      headers: {
        Accept: 'application/json',
        Authorization: `Bearer ${checkedCapability}`,
      },
      signal: abortAfter(SIGNAL_OPEN_TIMEOUT_MS, cancellation),
    });
  } catch {
    throwIfAborted(cancellation);
    throw new TurnProviderUnavailableError('could not fetch TURN credentials');
  }
  throwIfAborted(cancellation);

  if (response.status === 403) {
    let payload;
    try {
      payload = await readBoundedJson(response, MAX_TURN_ERROR_BYTES);
      throwIfAborted(cancellation);
    } catch {
      throwIfAborted(cancellation);
      throw new TurnProviderUnavailableError('TURN credential service returned an invalid denial');
    }
    if (isTurnNotAllowlistedPayload(payload)) throw new TurnPasskeyNotAllowlistedError();
    throw new TurnProviderUnavailableError('TURN credential service rejected the request');
  }
  if (!response.ok) {
    throw new TurnProviderUnavailableError('TURN credential service is unavailable');
  }

  try {
    const payload = await readBoundedJson(response, MAX_TURN_RESPONSE_BYTES);
    throwIfAborted(cancellation);
    return filterCloudflareIceServers(payload?.iceServers);
  } catch {
    throwIfAborted(cancellation);
    throw new TurnProviderUnavailableError('TURN credential service returned an invalid response');
  }
}

async function readBoundedJson(response, maximumBytes) {
  return JSON.parse(decoder.decode(await readBoundedBytes(response, maximumBytes)));
}

async function readBoundedBytes(response, maximumBytes) {
  const declaredLength = Number(response.headers.get('Content-Length'));
  if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
    throw new ProtocolError('response is too large');
  }
  if (!response.body?.getReader) {
    const bytes = new Uint8Array(await response.arrayBuffer());
    if (bytes.length > maximumBytes) throw new ProtocolError('response is too large');
    return bytes;
  }

  const reader = response.body.getReader();
  const chunks = [];
  let length = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > maximumBytes) {
      await reader.cancel();
      throw new ProtocolError('response is too large');
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}

let sasWordsPromise;

function loadSasWords() {
  if (sasWordsPromise) return sasWordsPromise;
  sasWordsPromise = fetch(new URL('./nearby-sas-words.txt', import.meta.url), {
    cache: 'force-cache',
    credentials: 'omit',
  }).then(async response => {
    if (!response.ok) throw new ProtocolError('could not load pairing words');
    return parseSasWordList(await readBoundedBytes(response, MAX_SAS_WORD_LIST_BYTES));
  });
  return sasWordsPromise;
}

function waitForIceGathering(peer) {
  if (peer.iceGatheringState === 'complete') return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      peer.removeEventListener('icegatheringstatechange', onChange);
      reject(new PeerConnectionEstablishmentError('timed out gathering ICE candidates'));
    }, ICE_GATHER_TIMEOUT_MS);
    function onChange() {
      if (peer.iceGatheringState !== 'complete') return;
      clearTimeout(timer);
      peer.removeEventListener('icegatheringstatechange', onChange);
      resolve();
    }
    peer.addEventListener('icegatheringstatechange', onChange);
  });
}

function expectDataChannel(peer) {
  return new Promise((resolve, reject) => {
    let claimed = false;
    const timer = setTimeout(
      () => reject(new PeerConnectionEstablishmentError('timed out opening the private channel')),
      DATA_CONNECT_TIMEOUT_MS,
    );

    function rejectOnFailure() {
      if (peer.connectionState === 'failed' || peer.connectionState === 'closed') {
        clearTimeout(timer);
        reject(new PeerConnectionEstablishmentError('the private connection failed'));
      }
    }
    peer.addEventListener('connectionstatechange', rejectOnFailure);
    peer.addEventListener('datachannel', event => {
      if (claimed) {
        event.channel.close();
        return;
      }
      claimed = true;
      const channel = event.channel;
      if (channel.label !== 'keytap/nearby'
          || channel.protocol !== 'keytap.nearby.v1'
          || !channel.ordered
          || channel.maxRetransmits !== null
          || channel.maxPacketLifeTime !== null) {
        clearTimeout(timer);
        channel.close();
        reject(new ProtocolError('the CLI opened an invalid data channel'));
        return;
      }
      waitForDataChannelOpen(channel).then(() => {
        clearTimeout(timer);
        peer.removeEventListener('connectionstatechange', rejectOnFailure);
        resolve(makeDataSession(peer, channel));
      }, error => {
        clearTimeout(timer);
        reject(error);
      });
    });
  });
}

function waitForDataChannelOpen(channel) {
  if (channel.readyState === 'open') return Promise.resolve();
  return new Promise((resolve, reject) => {
    channel.addEventListener('open', resolve, { once: true });
    channel.addEventListener('close', () => reject(new PeerConnectionEstablishmentError('the private channel closed')), { once: true });
    channel.addEventListener('error', () => reject(new PeerConnectionEstablishmentError('the private channel failed')), { once: true });
  });
}

export function makeDataSession(peer, channel, onCompletedElsewhere = handleCompletedElsewhere) {
  const incoming = new AsyncQueue();
  let decodeChain = Promise.resolve();
  const session = {
    send(message) {
      if (channel.readyState !== 'open') throw new ProtocolError('the private channel closed');
      const encoded = JSON.stringify(message);
      if (encoder.encode(encoded).length > MAX_DATA_BYTES) throw new ProtocolError('data message is too large');
      channel.send(encoded);
    },
    next(timeoutMs = DATA_MESSAGE_TIMEOUT_MS) {
      return incoming.next(timeoutMs);
    },
    close() {
      try { channel.close(); } catch { /* already closed */ }
      try { peer.close(); } catch { /* already closed */ }
    },
  };
  channel.addEventListener('message', event => {
    decodeChain = decodeChain.then(() => {
      if (typeof event.data !== 'string') throw new ProtocolError('invalid data message');
      if (encoder.encode(event.data).length > MAX_DATA_BYTES) throw new ProtocolError('data message is too large');
      const text = event.data;
      const message = JSON.parse(text);
      if (!message || typeof message !== 'object' || Array.isArray(message)) {
        throw new ProtocolError('invalid data message');
      }
      if (message.type === 'completed-elsewhere') {
        const keys = Object.keys(message);
        if (keys.length !== 1 || keys[0] !== 'type') {
          throw new ProtocolError('invalid completed-elsewhere message');
        }
        onCompletedElsewhere(session);
        return;
      }
      incoming.push(message);
    }).catch(error => incoming.fail(error instanceof Error ? error : new ProtocolError('invalid data message')));
  });
  channel.addEventListener('close', () => incoming.fail(new ProtocolError('the private channel closed')));
  channel.addEventListener('error', () => incoming.fail(new ProtocolError('the private channel failed')));
  peer.addEventListener('connectionstatechange', () => {
    if (peer.connectionState === 'failed' || peer.connectionState === 'closed') {
      incoming.fail(new ProtocolError('the private connection closed'));
    }
  });

  return session;
}

export class PeerConnectionEstablishmentError extends ProtocolError {
  constructor(message) {
    super(message);
    this.name = 'PeerConnectionEstablishmentError';
  }
}

async function answerOfferAttempt({
  signaling,
  verifier,
  sequence,
  iceServers,
  turnRequiredPolicy,
  cancellation,
}) {
  const attemptSignal = await abortable(
    waitForAttemptSignal(signaling, turnRequiredPolicy),
    cancellation,
  );
  switch (attemptSignal.kind) {
    case 'turn-required':
      return attemptSignal;
    case 'offer':
      break;
  }
  const offerBytes = await abortable(
    verifier.verifyOffer(attemptSignal.envelope, sequence),
    cancellation,
  );
  if (offerBytes.length === 0 || offerBytes.length > MAX_SIGNAL_BYTES) {
    throw new ProtocolError('invalid authenticated offer');
  }
  let offerSdp;
  try {
    offerSdp = decoder.decode(offerBytes);
  } catch {
    throw new ProtocolError('authenticated offer is not UTF-8');
  }

  if (typeof RTCPeerConnection !== 'function') {
    throw new ProtocolError('WebRTC is unavailable in this browser');
  }
  const peer = new RTCPeerConnection({ iceServers });
  const closePeerOnAbort = () => peer.close();
  cancellation.addEventListener('abort', closePeerOnAbort, { once: true });
  const channelPromise = expectDataChannel(peer).then(
    session => ({ kind: 'open', session }),
    error => ({ kind: 'failed', error }),
  );
  try {
    // No SDP, including its DTLS fingerprint, reaches WebRTC before the
    // approval-link key authenticates the exact offer and attempt sequence.
    await abortable(peer.setRemoteDescription({ type: 'offer', sdp: offerSdp }), cancellation);
    const answer = await abortable(peer.createAnswer(), cancellation);
    await abortable(peer.setLocalDescription(answer), cancellation);
    await abortable(waitForIceGathering(peer), cancellation);
    const answerSdp = peer.localDescription?.sdp;
    if (typeof answerSdp !== 'string' || answerSdp.length === 0) {
      throw new ProtocolError('could not create a complete WebRTC answer');
    }
    signaling.send({
      v: 1,
      from: 'approver',
      seq: sequence,
      kind: 'answer',
      body: encodeBase64URL(encoder.encode(answerSdp)),
    });
    const channel = await abortable(channelPromise, cancellation);
    if (channel.kind === 'failed') throw channel.error;
    const sessionBinding = await abortable(createNearbySessionBinding(
      verifier.cliPublicKey,
      offerBytes,
      encoder.encode(answerSdp),
    ), cancellation);
    signaling.connectionEstablished();
    cancellation.removeEventListener('abort', closePeerOnAbort);
    return { kind: 'connected', session: channel.session, sessionBinding };
  } catch (error) {
    cancellation.removeEventListener('abort', closePeerOnAbort);
    peer.close();
    throw error;
  }
}

function directIceServers() {
  return CLOUDFLARE_STUN_ONLY.map(server => ({ urls: [...server.urls] }));
}

async function waitForRelayConsent(connection, cancellation) {
  say('The direct connection failed. Approve with an allowlisted passkey to use the TURN relay…');
  $('title').textContent = 'Use your passkey for relay access';
  $('summary').textContent = 'TURN is restricted because it consumes shared Cloudflare quota.';
  const button = $('start');
  button.hidden = false;
  button.disabled = false;
  button.textContent = 'Use passkey for relay';
  await abortable(new Promise(resolve => {
    phase = {
      kind: 'relay-consent',
      data: { connection, proceed: resolve },
    };
  }), cancellation);
}

/**
 * @param {unknown} error
 * @returns {TurnRetryControl}
 */
export function turnUnavailableControl(error) {
  if (error instanceof TurnPasskeyNotAllowlistedError) {
    return { type: 'turn-unavailable', reason: 'not-allowlisted' };
  }
  if (error instanceof TurnPasskeyCancelledError) {
    return { type: 'turn-unavailable', reason: 'cancelled' };
  }
  if (error instanceof TurnPasskeyUnavailableError) {
    return { type: 'turn-unavailable', reason: 'passkey-unavailable' };
  }
  return { type: 'turn-unavailable', reason: 'provider-unavailable' };
}

/**
 * @param {TurnCapability} capability
 * @returns {TurnRetryControl}
 */
export function turnAuthorizedControl(capability) {
  return { type: 'turn-authorized', capability: requireTurnCapability(capability) };
}

function notifyTurnUnavailable(sendTurnControl, error) {
  try { sendTurnControl(turnUnavailableControl(error)); } catch { /* signaling is already closed */ }
}

/** @returns {Promise<AuthorizedRelay>} */
async function prepareAuthorizedRelay(rendezvousId, challenge, cancellation) {
  const capability = await authorizeTurnWithPasskey(
    rendezvousId,
    challenge,
    cancellation,
  );
  const iceServers = await fetchTurnIceServers(rendezvousId, capability, cancellation);
  return { capability, iceServers };
}

/**
 * Run the direct-to-relay transition independently from DOM and WebRTC
 * mechanics so its ordering and cancellation rules stay explicit.
 *
 * @param {{
 *   cancellation: AbortSignal,
 *   sendTurnControl: (message: TurnRetryControl) => void,
 *   attemptConnection: (spec: ConnectionAttemptSpec) => Promise<ConnectionAttemptOutcome>,
 *   requestRelayChallenge: () => Promise<TurnPasskeyChallenge>,
 *   waitForConsent: () => Promise<void>,
 *   prepareRelay: (challenge: TurnPasskeyChallenge) => Promise<AuthorizedRelay>,
 *   onRelayAuthorized: () => void,
 * }} operations
 * @returns {Promise<{session: DataSession, sessionBinding: Uint8Array}>}
 */
export async function runConnectionAttemptProtocol({
  cancellation,
  sendTurnControl,
  attemptConnection,
  requestRelayChallenge,
  waitForConsent,
  prepareRelay,
  onRelayAuthorized,
}) {
  let directOutcome;
  try {
    throwIfAborted(cancellation);
    // Attempt zero is always STUN-only. Relay authorization and Cloudflare
    // allocation remain unreachable until direct connectivity has failed.
    directOutcome = await abortable(attemptConnection({
      sequence: 0,
      iceServers: directIceServers(),
      turnRequiredPolicy: 'accept',
    }), cancellation);
  } catch (error) {
    throwIfAborted(cancellation);
    if (!(error instanceof PeerConnectionEstablishmentError)) throw error;
    directOutcome = { kind: 'turn-required' };
  }
  switch (directOutcome.kind) {
    case 'connected':
      return {
        session: directOutcome.session,
        sessionBinding: directOutcome.sessionBinding,
      };
    case 'turn-required':
      break;
    default:
      throw new ProtocolError('invalid direct connection outcome');
  }

  await abortable(waitForConsent(), cancellation);

  let relay;
  try {
    throwIfAborted(cancellation);
    const challenge = await abortable(requestRelayChallenge(), cancellation);
    relay = await abortable(prepareRelay(challenge), cancellation);
  } catch (error) {
    throwIfAborted(cancellation);
    notifyTurnUnavailable(sendTurnControl, error);
    throw error;
  }

  // Do not disclose a freshly created capability if signaling cancellation
  // won the race immediately after authorization completed.
  throwIfAborted(cancellation);
  sendTurnControl(turnAuthorizedControl(relay.capability));
  onRelayAuthorized();
  throwIfAborted(cancellation);
  const relayOutcome = await abortable(attemptConnection({
    sequence: 1,
    iceServers: relay.iceServers,
    turnRequiredPolicy: 'ignore-stale',
  }), cancellation);
  switch (relayOutcome.kind) {
    case 'connected':
      return {
        session: relayOutcome.session,
        sessionBinding: relayOutcome.sessionBinding,
      };
    case 'turn-required':
      throw new ProtocolError('unexpected TURN retry signaling state');
    default:
      throw new ProtocolError('invalid TURN connection outcome');
  }
}

async function establishPrivateChannel(verifier, connection) {
  const cancellation = connection.controller.signal;
  const signaling = await openSignalSocket(verifier.rendezvousId, connection);
  try {
    await abortable(waitForPeer(signaling), cancellation);
    say('Found your CLI. Trying a direct peer-to-peer connection…');
    const established = await runConnectionAttemptProtocol({
      cancellation,
      sendTurnControl: message => signaling.send(message),
      attemptConnection: spec => answerOfferAttempt({
        signaling,
        verifier,
        cancellation,
        ...spec,
      }),
      requestRelayChallenge: () => fetchTurnPasskeyChallenge(
        verifier.rendezvousId,
        cancellation,
      ),
      waitForConsent: () => waitForRelayConsent(connection, cancellation),
      prepareRelay: challenge => {
        if (phase.kind !== 'relay-authorizing' || phase.data !== connection) {
          throw abortFailure(cancellation);
        }
        say('Waiting for passkey approval…');
        return prepareAuthorizedRelay(verifier.rendezvousId, challenge, cancellation);
      },
      onRelayAuthorized: () => {
        phase = { kind: 'connecting-relay', data: connection };
        $('start').hidden = true;
        say('Passkey approved. Establishing the TURN-relayed private connection…');
      },
    });
    $('start').hidden = true;
    return established;
  } finally {
    signaling.close();
  }
}

function beginRelayAuthorization() {
  if (phase.kind !== 'relay-consent') return;
  const { connection, proceed } = phase.data;
  phase = { kind: 'relay-authorizing', data: connection };
  const button = $('start');
  button.disabled = true;
  button.textContent = 'Preparing relay…';
  document.title = 'keytap: approve relay';
  say('Preparing passkey authorization for the TURN relay…');
  proceed();
}

function expectObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ProtocolError(`invalid ${label}`);
  }
  return value;
}

function expectExactObject(value, expectedKeys, label) {
  const object = expectObject(value, label);
  if (!hasExactKeys(object, expectedKeys)) throw new ProtocolError(`invalid ${label}`);
  return object;
}

function expectString(value, label, maxLength = 256) {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) {
    throw new ProtocolError(`invalid ${label}`);
  }
  return value;
}

function expectBytes(value, label, minimum, maximum) {
  const bytes = decodeBase64URL(expectString(value, label, Math.ceil(maximum * 4 / 3) + 4));
  if (bytes.length < minimum || bytes.length > maximum) throw new ProtocolError(`invalid ${label}`);
  return bytes;
}

function parseIdentityMode(value) {
  const identity = expectObject(value, 'identity mode');
  switch (identity.kind) {
    case 'pairing-any':
      expectExactObject(identity, ['kind'], 'identity mode');
      return { kind: 'pairing-any' };
    case 'pairing-credential':
      expectExactObject(identity, ['kind', 'credentialId'], 'identity mode');
      return {
        kind: 'pairing-credential',
        credentialId: expectBytes(identity.credentialId, 'pairing credential ID', 1, 1024),
      };
    case 'pinned':
      expectExactObject(identity, ['kind', 'credentialId'], 'identity mode');
      return {
        kind: 'pinned',
        credentialId: expectBytes(identity.credentialId, 'pinned credential ID', 1, 1024),
      };
    default:
      throw new ProtocolError('invalid identity mode');
  }
}

function parseRequest(value) {
  const request = expectObject(value, 'request');
  switch (request.kind) {
    case 'register':
      expectExactObject(
        request,
        ['kind', 'challenge', 'prfSalt', 'userId', 'userName'],
        'registration request',
      );
      return {
        kind: 'register',
        challenge: expectBytes(request.challenge, 'challenge', 16, 128),
        prfSalt: expectBytes(request.prfSalt, 'PRF salt', 32, 32),
        userId: expectBytes(request.userId, 'user ID', 1, 64),
        userName: expectString(request.userName, 'user name'),
      };
    case 'assert':
      expectExactObject(
        request,
        ['kind', 'challenge', 'prfSalt', 'identitySalt', 'identity', 'keyName', 'storage'],
        'assertion request',
      );
      break;
    default:
      throw new ProtocolError('unsupported nearby request');
  }
  const storage = request.storage;
  if (storage !== 'choose' && storage !== 'remember') {
    throw new ProtocolError('invalid storage policy');
  }
  return {
    kind: 'assert',
    challenge: expectBytes(request.challenge, 'challenge', 16, 128),
    prfSalt: expectBytes(request.prfSalt, 'PRF salt', 32, 32),
    identitySalt: expectBytes(request.identitySalt, 'identity PRF salt', 32, 32),
    identity: parseIdentityMode(request.identity),
    keyName: expectString(request.keyName, 'key name'),
    storage,
  };
}

export function parseInitialRequest(value) {
  const message = expectObject(value, 'request message');
  switch (message.type) {
    case 'request':
      expectExactObject(message, ['type', 'request'], 'request message');
      break;
    case 'pairing-request':
      expectExactObject(
        message,
        ['type', 'request', 'cliCommitment'],
        'pairing request message',
      );
      break;
    default:
      throw new ProtocolError('expected a nearby request');
  }
  const request = parseRequest(message.request);
  switch (message.type) {
    case 'request':
      if (request.kind !== 'assert' || request.identity.kind !== 'pinned') {
        throw new ProtocolError('an unpaired request cannot skip SAS');
      }
      return { kind: 'pinned', request };
    case 'pairing-request':
      break;
  }
  const cliCommitment = expectBytes(
    message.cliCommitment,
    'CLI pairing commitment',
    32,
    32,
  );
  switch (request.kind) {
    case 'register':
      return { kind: 'pairing', request, cliCommitment };
    case 'assert':
      switch (request.identity.kind) {
        case 'pairing-any':
        case 'pairing-credential':
          return { kind: 'pairing', request, cliCommitment };
        case 'pinned':
          throw new ProtocolError('a pinned request cannot restart pairing');
      }
  }
  throw new ProtocolError('invalid initial request state');
}

async function nextSasCliReveal(session) {
  const message = parseCliMessage(await session.next(), 'sas-cli-reveal');
  return expectBytes(message.nonce, 'CLI pairing nonce', 32, 32);
}

async function startPairing(session, request, sessionBinding, cliCommitment) {
  const context = await createSasContext(sessionBinding, request);
  if (phase.kind !== 'awaiting-request' || phase.session !== session) return;
  const approverNonce = crypto.getRandomValues(new Uint8Array(32));
  const approverCommitment = await createSasCommitment('approver', context, approverNonce);
  if (phase.kind !== 'awaiting-request' || phase.session !== session) {
    approverNonce.fill(0);
    return;
  }
  session.send({
    type: 'sas-approver-commit',
    commitment: encodeBase64URL(approverCommitment),
  });
  const cliNonce = await nextSasCliReveal(session);
  if (phase.kind !== 'awaiting-request' || phase.session !== session) {
    approverNonce.fill(0);
    cliNonce.fill(0);
    return;
  }
  if (!await verifySasCommitment('cli', context, cliNonce, cliCommitment)) {
    session.send({ type: 'sas-approver-rejected' });
    throw new ProtocolError('the CLI did not open its pairing commitment');
  }
  session.send({
    type: 'sas-approver-reveal',
    nonce: encodeBase64URL(approverNonce),
  });
  const digest = await createSasDigest(
    context,
    cliCommitment,
    approverCommitment,
    cliNonce,
    approverNonce,
  );
  cliNonce.fill(0);
  approverNonce.fill(0);
  const words = await loadSasWords();
  if (phase.kind !== 'awaiting-request' || phase.session !== session) {
    digest.fill(0);
    return;
  }
  $('pairing-words').textContent = sasPhrase(digest, words);
  $('pairing-copy').textContent = request.kind === 'assert'
    ? 'Choose below, then finish the passkey step here. Afterward, confirm these words once in the terminal.'
    : 'Finish the passkey step here. The result is sent to the CLI, which buffers it until you compare both words, in order, and confirm them once in the terminal that displayed the approval link.';
  $('pairing').hidden = false;
  $('start').hidden = true;
  $('title').textContent = request.kind === 'register'
    ? 'Create your passkey'
    : 'Approve this key request';
  $('summary').textContent = 'Keep these words visible so you can compare them in your terminal afterward.';
  $('explainer').textContent = 'Finish the passkey step on this device first. The CLI will buffer its result and refuse to use it unless you confirm the words.';
  $('pairing-heading').focus();
  const base = {
    session,
    binding: { kind: 'bootstrap-sas', digest },
  };
  if (request.kind === 'register') {
    const data = { ...base, kind: 'registration', request, controller: new AbortController() };
    phase = { kind: 'pairing-ceremony', data };
    await runPairingCeremony(data);
    return;
  }
  enterDispositionChoice({ kind: 'pairing', ...base, request });
}

async function runPairingCeremony(data) {
  say(data.kind === 'registration'
    ? 'Creating your passkey…'
    : 'Waiting for passkey approval…');
  let completed;
  try {
    if (data.kind === 'registration') {
      completed = {
        kind: 'registration',
        credential: await runRegister(data.request, data.controller.signal),
      };
    } else {
      completed = {
        kind: 'assertion',
        result: await runInitialAssertion(
          data.request,
          data.binding,
          data.disposition,
          data.controller.signal,
        ),
      };
    }
  } catch (error) {
    if (phase.kind !== 'pairing-ceremony' || phase.data !== data) return;
    if (data.kind === 'assertion' && isCancel(error)) {
      enterDispositionChoice({
        kind: 'pairing',
        session: data.session,
        binding: data.binding,
        request: data.request,
      });
      say('The passkey prompt was cancelled or didn’t open. Nothing was sent. Choose again to retry.');
      (data.disposition === 'once' ? $('done-btn') : $('remember-btn')).focus();
      return;
    }
    try { data.session.send({ type: 'sas-approver-rejected' }); } catch { /* closed */ }
    failSession(data.session, error);
    return;
  }

  if (phase.kind !== 'pairing-ceremony' || phase.data !== data) {
    if (completed.kind === 'assertion') completed.result.prfFirst.fill(0);
    return;
  }
  try {
    if (completed.kind === 'registration') {
      sendPairedRegistrationResult(data.session, completed.credential);
      phase = { kind: 'registration-ack', session: data.session };
      say('Result sent. Confirm the words in your terminal; the CLI will not save it unless they match.');
      await nextCliMessage(data.session, 'initial-accepted');
      if (phase.kind !== 'registration-ack' || phase.session !== data.session) return;
      finishRegistration(data.session);
      return;
    }

    sendPairedAssertionResult(data.session, completed.result, data.disposition);
    const assertionData = {
      session: data.session,
      request: data.request,
      disposition: data.disposition,
    };
    phase = { kind: 'assertion-ack', data: assertionData };
    say('Result sent. Confirm the words in your terminal; the CLI will not use or trust it unless they match.');
    await finishAcceptedAssertion(assertionData);
  } catch (error) {
    failSession(data.session, error);
  }
}

export function parseCliMessage(value, expectedType) {
  const message = expectObject(value, 'CLI message');
  if (typeof message.type !== 'string') throw new ProtocolError('invalid CLI message');
  if (message.type === 'protocol-error') {
    if (!hasExactKeys(message, ['type', 'code'])) {
      throw new ProtocolError('invalid CLI protocol error');
    }
    const codes = new Set(['invalid-message', 'unexpected-message']);
    if (!codes.has(message.code)) throw new ProtocolError('invalid CLI protocol error');
    throw new ProtocolError(`the CLI rejected the request (${message.code})`);
  }
  if (message.type === 'initial-rejected') {
    if (!hasExactKeys(message, ['type', 'reason'])) {
      throw new ProtocolError('invalid CLI identity rejection');
    }
    const reasons = new Set(['identity-mismatch', 'invalid-identity-proof', 'identity-store-unavailable']);
    if (!reasons.has(message.reason)) throw new ProtocolError('invalid CLI identity rejection');
    throw new InitialRejectionError(message.reason);
  }
  if (message.type === 'initial-indeterminate') {
    if (!hasExactKeys(message, ['type', 'reason'])
        || message.reason !== 'identity-durability-unknown') {
      throw new ProtocolError('invalid CLI identity status');
    }
    throw new InitialIndeterminateError(message.reason);
  }
  if (message.type === 'sas-cli-rejected') {
    if (!hasExactKeys(message, ['type'])) {
      throw new ProtocolError('invalid CLI pairing rejection');
    }
    throw new PairingRejectedError();
  }
  if (message.type !== expectedType) throw new ProtocolError(`expected ${expectedType}`);
  switch (expectedType) {
    case 'sas-cli-reveal':
      return expectExactObject(message, ['type', 'nonce'], 'CLI SAS reveal');
    case 'initial-accepted':
      return expectExactObject(message, ['type'], 'initial acknowledgement');
    case 'assertion-accepted':
      expectExactObject(message, ['type', 'storage'], 'assertion acknowledgement');
      if (message.storage !== 'once'
          && message.storage !== 'stored'
          && message.storage !== 'unavailable') {
        throw new ProtocolError('invalid assertion acknowledgement');
      }
      return message;
    default:
      throw new ProtocolError('invalid expected CLI message type');
  }
}

async function nextCliMessage(session, expectedType) {
  return parseCliMessage(await session.next(), expectedType);
}

class InitialRejectionError extends ProtocolError {
  constructor(reason) {
    super(`the CLI rejected the passkey identity (${reason})`);
    this.name = 'InitialRejectionError';
    this.reason = reason;
  }
}

class InitialIndeterminateError extends ProtocolError {
  constructor(reason) {
    super(`the CLI could not determine whether the passkey identity is durable (${reason})`);
    this.name = 'InitialIndeterminateError';
    this.reason = reason;
  }
}

class PairingRejectedError extends ProtocolError {
  constructor() {
    super('the CLI did not confirm the pairing words');
    this.name = 'PairingRejectedError';
  }
}

export function initialRejectionMessage(reason, registration) {
  if (reason === 'identity-store-unavailable') {
    return registration
      ? 'The CLI received the passkey result but could not save the trusted identity. Run init again.'
      : 'The CLI could not access its trusted identity store, so no key was accepted. Check that machine and run the command again.';
  }
  return 'This passkey did not match the identity already trusted by the CLI, so no key was accepted.';
}

export function initialIndeterminateMessage(registration) {
  return registration
    ? 'Setup status unknown. The CLI received the new passkey but could not confirm that its identity was saved durably. Do not rely on it; check the terminal and rerun keytap init --force. The passkey may remain on this device.'
    : 'Pairing status unknown. The CLI refused the returned key because it could not confirm that the identity was saved durably. Check the terminal, then retry with a fresh approval link.';
}

export function storageUnavailableMessage() {
  return 'The CLI received the approved key but could not store it on that machine. Check the terminal before trying again.';
}

export function sessionFailureMessage(error, phaseKind) {
  if (error instanceof PairingRejectedError) {
    return phaseKind === 'registration-ack'
      ? 'The result was sent, but the CLI discarded it because the pairing words were not confirmed. The passkey may remain on this device; run init again with a fresh approval link.'
      : 'The result was sent, but the CLI discarded it and trusted nothing because the pairing words were not confirmed. Run the command again with a fresh approval link.';
  }
  if (error instanceof InitialRejectionError) {
    return initialRejectionMessage(error.reason, phaseKind === 'registration-ack');
  }
  if (error instanceof InitialIndeterminateError) {
    return initialIndeterminateMessage(phaseKind === 'registration-ack');
  }
  switch (phaseKind) {
    case 'registration-ack':
      return 'The passkey result was sent, but this approval page could not confirm whether the CLI saved it. Check the terminal before retrying; a passkey may already have been paired.';
    case 'assertion-ack':
      return 'The key result was sent, but this approval page could not confirm whether the CLI accepted it. Check the terminal before retrying.';
    default:
      return 'The private connection failed. Nothing else was sent. Run the command again and open the fresh approval link.';
  }
}

async function nextAssertionOutcome(session) {
  const message = await nextCliMessage(session, 'assertion-accepted');
  return message.storage;
}

function runRegister(request, signal) {
  return navigator.credentials.create({
    signal,
    publicKey: {
      challenge: request.challenge,
      rp: { id: 'keytap.jul.sh', name: 'keytap' },
      user: { id: request.userId, name: request.userName, displayName: request.userName },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      attestation: 'none',
      timeout: 120_000,
      extensions: { prf: { eval: { first: request.prfSalt } } },
    },
  }).then(credential => {
    if (!credential?.rawId) throw new Error('Passkey creation returned no credential.');
    if (!credential.getClientExtensionResults()?.prf?.enabled) {
      throw new Error('Passkey created but this authenticator does not support PRF.');
    }
    return credential;
  });
}

async function runInitialAssertion(request, binding, disposition, signal) {
  const publicKey = {
    challenge: request.challenge,
    rpId: 'keytap.jul.sh',
    userVerification: 'required',
    timeout: 120_000,
    extensions: {
      prf: { eval: { first: request.prfSalt, second: request.identitySalt } },
    },
  };
  if (request.identity.kind === 'pinned' || request.identity.kind === 'pairing-credential') {
    publicKey.allowCredentials = [{ type: 'public-key', id: request.identity.credentialId }];
  }
  const credential = await navigator.credentials.get({ publicKey, signal });
  const prfResults = credential?.getClientExtensionResults()?.prf?.results;
  const prfFirst = prfResults?.first;
  const prfSecond = prfResults?.second;
  if (!credential?.rawId || !prfFirst || !prfSecond) {
    throw new Error('Both key and identity PRF outputs are required.');
  }
  const credentialId = new Uint8Array(credential.rawId);
  const prfFirstBytes = new Uint8Array(prfFirst);
  const prfSecondBytes = new Uint8Array(prfSecond);
  let identity;
  try {
    identity = await createNearbyIdentityProof({
      binding,
      challenge: request.challenge,
      credentialId,
      prfFirst: prfFirstBytes,
      keyName: request.keyName,
      disposition,
    }, prfSecondBytes, deriveEd25519PublicKey);
  } catch (error) {
    prfFirstBytes.fill(0);
    throw error;
  } finally {
    prfSecondBytes.fill(0);
  }
  return {
    credentialId,
    prfFirst: prfFirstBytes,
    identity: {
      algorithm: 'ed25519',
      publicKey: encodeBase64URL(identity.publicKey),
      signature: encodeBase64URL(identity.signature),
    },
  };
}

function sendAssertionResult(session, result, disposition) {
  try {
    session.send({
      type: 'assertion-result',
      credentialId: encodeBase64URL(result.credentialId),
      prfFirst: encodeBase64URL(result.prfFirst),
      identity: result.identity,
      disposition,
    });
  } finally {
    result.prfFirst.fill(0);
  }
}

export function sendPairedRegistrationResult(session, credential) {
  session.send({
    type: 'paired-registration-result',
    credentialId: encodeBase64URL(credential.rawId),
  });
}

export function sendPairedAssertionResult(session, result, disposition) {
  try {
    session.send({
      type: 'paired-assertion-result',
      credentialId: encodeBase64URL(result.credentialId),
      prfFirst: encodeBase64URL(result.prfFirst),
      identity: result.identity,
      disposition,
    });
  } finally {
    result.prfFirst.fill(0);
  }
}

function isCancel(error) {
  return error && (error.name === 'NotAllowedError' || error.name === 'AbortError');
}

function configurePinnedRequest(session, request, sessionBinding) {
  $('pairing').hidden = true;
  $('title').textContent = 'Approve this key request';
  render($('summary'), 'Your CLI requested key: ', { code: request.keyName });
  $('explainer').textContent = 'Choose how the CLI machine should use it, then approve once with your passkey.';
  enterDispositionChoice({
    kind: 'pinned',
    session,
    request,
    sessionBinding,
  });
}

async function runPinnedAssertion(source, disposition) {
  const data = {
    session: source.session,
    request: source.request,
    sessionBinding: source.sessionBinding,
    controller: new AbortController(),
    disposition,
  };
  phase = { kind: 'first-busy', data };
  $('offer').hidden = true;
  document.title = 'keytap: approve';

  say('Waiting for passkey approval…');
  let firstResult;
  try {
    firstResult = await runInitialAssertion(data.request, {
      kind: 'pinned-session',
      digest: data.sessionBinding,
    }, disposition, data.controller.signal);
  } catch (error) {
    restoreAfterCeremonyError(data, error);
    return;
  }
  if (phase.kind !== 'first-busy' || phase.data !== data) {
    firstResult.prfFirst.fill(0);
    return;
  }
  try {
    sendAssertionResult(data.session, firstResult, disposition);
    const assertionData = {
      session: data.session,
      request: data.request,
      disposition,
    };
    phase = { kind: 'assertion-ack', data: assertionData };
    await finishAcceptedAssertion(assertionData);
  } catch (error) {
    failSession(data.session, error);
  }
}

function restoreAfterCeremonyError(data, error) {
  if (phase.kind !== 'first-busy' || phase.data !== data) return;
  document.title = 'keytap';
  enterDispositionChoice({
    kind: 'pinned',
    session: data.session,
    request: data.request,
    sessionBinding: data.sessionBinding,
  });
  if (isCancel(error)) {
    say('The passkey prompt was cancelled or didn’t open. Nothing was sent. Choose again to retry.');
  } else {
    console.error(error);
    const detail = error instanceof Error && error.message
      ? error.message
      : 'The passkey ceremony failed.';
    alertUser(detail);
  }
  (data.disposition === 'once' ? $('done-btn') : $('remember-btn')).focus();
}

function completedElsewhereAbortReason() {
  return new DOMException('Approval completed on the Mac.', 'AbortError');
}

function closeForCompletedElsewhere(session) {
  session.close();
  return { kind: 'completed-elsewhere' };
}

function abortAndCloseForCompletedElsewhere(controller, session) {
  controller.abort(completedElsewhereAbortReason());
  return closeForCompletedElsewhere(session);
}

/**
 * Cancel work owned by the current phase after the authenticated CLI reports
 * that its local passkey approval won. Returning the same phase means that the
 * message came from a stale session or arrived after a terminal transition.
 *
 * @param {Phase} currentPhase
 * @param {DataSession} sourceSession
 * @returns {Phase}
 */
export function terminatePhaseForCompletedElsewhere(currentPhase, sourceSession) {
  switch (currentPhase.kind) {
    case 'connecting-direct':
    case 'relay-authorizing':
    case 'connecting-relay':
      currentPhase.data.controller.abort(completedElsewhereAbortReason());
      return closeForCompletedElsewhere(sourceSession);
    case 'relay-consent':
      currentPhase.data.connection.controller.abort(completedElsewhereAbortReason());
      return closeForCompletedElsewhere(sourceSession);
    case 'first-busy':
      if (currentPhase.data.session !== sourceSession) {
        sourceSession.close();
        return currentPhase;
      }
      return abortAndCloseForCompletedElsewhere(currentPhase.data.controller, sourceSession);
    case 'pairing-ceremony':
      if (currentPhase.data.session !== sourceSession) {
        sourceSession.close();
        return currentPhase;
      }
      return abortAndCloseForCompletedElsewhere(currentPhase.data.controller, sourceSession);
    case 'awaiting-request':
    case 'registration-ack':
      if (currentPhase.session !== sourceSession) {
        sourceSession.close();
        return currentPhase;
      }
      return closeForCompletedElsewhere(sourceSession);
    case 'disposition-choice':
    case 'assertion-ack':
      if (currentPhase.data.session !== sourceSession) {
        sourceSession.close();
        return currentPhase;
      }
      return closeForCompletedElsewhere(sourceSession);
    case 'boot':
    case 'completed-elsewhere':
    case 'finished':
    case 'failed':
    case 'expired':
      sourceSession.close();
      return currentPhase;
  }
  throw new ProtocolError('invalid nearby lifecycle phase');
}

/**
 * @param {Phase} currentPhase
 * @param {ConnectingData} connection
 * @returns {Phase}
 */
export function terminateConnectionPhaseForCompletedElsewhere(currentPhase, connection) {
  switch (currentPhase.kind) {
    case 'connecting-direct':
    case 'relay-authorizing':
    case 'connecting-relay':
      if (currentPhase.data !== connection) return currentPhase;
      connection.controller.abort(completedElsewhereAbortReason());
      return { kind: 'completed-elsewhere' };
    case 'relay-consent':
      if (currentPhase.data.connection !== connection) return currentPhase;
      connection.controller.abort(completedElsewhereAbortReason());
      return { kind: 'completed-elsewhere' };
    case 'boot':
    case 'awaiting-request':
    case 'disposition-choice':
    case 'first-busy':
    case 'pairing-ceremony':
    case 'registration-ack':
    case 'assertion-ack':
    case 'completed-elsewhere':
    case 'finished':
    case 'failed':
    case 'expired':
      return currentPhase;
  }
  throw new ProtocolError('invalid nearby lifecycle phase');
}

export function renderCompletedElsewhere() {
  document.title = 'keytap: approved on Mac';
  $('title').textContent = 'Approved on the Mac';
  $('summary').hidden = true;
  $('explainer').hidden = true;
  $('details').hidden = true;
  $('start')?.remove();
  $('offer').hidden = true;
  $('pairing').hidden = true;
  say('The passkey approval on the Mac completed first, so this device’s approval was not used. You can close this page.');
  $('status').focus();
}

function handleCompletedElsewhere(session) {
  const currentPhase = phase;
  const nextPhase = terminatePhaseForCompletedElsewhere(currentPhase, session);
  if (nextPhase === currentPhase) return;
  phase = nextPhase;
  renderCompletedElsewhere();
}

function finishRegistration(session) {
  phase = { kind: 'finished' };
  document.title = 'keytap: sent';
  $('title').textContent = 'Passkey created';
  $('summary').hidden = true;
  $('explainer').hidden = true;
  $('details').hidden = true;
  $('start')?.remove();
  $('offer').hidden = true;
  $('pairing').hidden = true;
  say('Sent to your CLI. You can close this page.');
  $('status').focus();
  setTimeout(() => session.close(), 750);
}

function finishAssertion(session, request, disposition) {
  phase = { kind: 'finished' };
  document.title = disposition === 'remember' ? 'keytap: remembered' : 'keytap: sent';
  $('title').textContent = disposition === 'remember' ? 'Key remembered' : 'Key sent';
  $('summary').hidden = true;
  $('explainer').hidden = true;
  $('details').hidden = true;
  $('start')?.remove();
  $('offer').hidden = true;
  $('pairing').hidden = true;
  if (disposition === 'remember') {
    say(
      'Sent and stored on that machine. Remove it later with ',
      { code: `keytap forget ${request.keyName}` },
      '. You can close this page.',
    );
  } else {
    say('Sent for this command. The named derived key was not stored on that machine. You can close this page.');
  }
  $('status').focus();
  setTimeout(() => session.close(), 750);
}

function setDispositionButtonsDisabled(disabled) {
  for (const button of [$('remember-btn'), $('done-btn')]) {
    button.disabled = disabled;
    button.setAttribute('aria-disabled', disabled ? 'true' : 'false');
  }
}

function enterDispositionChoice(data) {
  const request = data.request;
  const choose = request.storage === 'choose';
  const onceButton = $('done-btn');
  const rememberButton = $('remember-btn');

  phase = { kind: 'disposition-choice', data };
  $('start').hidden = true;
  $('offer-heading').textContent = choose ? 'Use once or remember?' : 'Approve and remember?';
  render(
    $('offer-body'),
    choose ? 'Use ' : 'Store ', { code: request.keyName },
    choose
      ? ' for this command only, or store it on that machine so future commands there won’t need another approval.'
      : ' on that machine so future commands there won’t need another approval.',
  );
  render(
    $('offer-hint'),
    choose
      ? 'Use once does not store the named derived key. If you remember it, remove it later with '
      : 'Remove it later with ',
    { code: `keytap forget ${request.keyName}` },
    '.',
  );

  if (!choose) {
    onceButton.hidden = true;
    rememberButton.textContent = 'Approve and remember';
    rememberButton.classList.remove('action-secondary');
  }
  setDispositionButtonsDisabled(false);
  $('offer').hidden = false;

  if (data.kind === 'pairing') {
    $('explainer').textContent = 'Choose below, finish the passkey step on this device, then confirm the two words in your terminal.';
    say('Choose how to use this key, then approve with your passkey.');
  } else {
    say(choose ? 'Choose how to use this key.' : 'Approve once to store this key on that machine.');
  }
  $('offer-heading').focus();
}

function chooseDisposition(disposition) {
  if (phase.kind !== 'disposition-choice') return;
  const source = phase.data;
  if (source.request.storage === 'remember' && disposition !== 'remember') return;
  setDispositionButtonsDisabled(true);
  if (source.kind === 'pinned') {
    runPinnedAssertion(source, disposition);
    return;
  }
  const data = {
    kind: 'assertion',
    session: source.session,
    binding: source.binding,
    request: source.request,
    disposition,
    controller: new AbortController(),
  };
  phase = { kind: 'pairing-ceremony', data };
  $('offer').hidden = true;
  runPairingCeremony(data);
}

async function finishAcceptedAssertion(data) {
  const storage = await nextAssertionOutcome(data.session);
  if (phase.kind !== 'assertion-ack' || phase.data !== data) return;
  if (data.disposition === 'once') {
    if (storage !== 'once') throw new ProtocolError('CLI acknowledged the wrong storage disposition');
    finishAssertion(data.session, data.request, 'once');
    return;
  }
  if (storage === 'stored') {
    finishAssertion(data.session, data.request, 'remember');
    return;
  }
  if (storage !== 'unavailable') {
    throw new ProtocolError('CLI acknowledged the wrong storage disposition');
  }
  phase = { kind: 'finished' };
  $('offer').hidden = true;
  $('pairing').hidden = true;
  $('summary').hidden = true;
  $('explainer').hidden = true;
  $('details').hidden = true;
  $('start')?.remove();
  document.title = 'keytap: not remembered';
  $('title').textContent = 'Could not remember key';
  alertUser(storageUnavailableMessage());
  $('alert').focus();
  setTimeout(() => data.session.close(), 750);
}

function failSession(session, error) {
  if (phase.kind === 'failed'
      || phase.kind === 'completed-elsewhere'
      || phase.kind === 'finished'
      || phase.kind === 'expired') return;
  const failedPhase = phase.kind;
  session.close();
  phase = { kind: 'failed' };
  $('offer').hidden = true;
  $('pairing').hidden = true;
  $('start')?.remove();
  document.title = 'keytap: connection failed';
  alertUser(sessionFailureMessage(error, failedPhase));
  $('alert').focus();
}

export function beforeSessionFailureMessage(error) {
  if (error instanceof TurnPasskeyNotAllowlistedError) {
    return 'The direct peer-to-peer connection failed, and this passkey identity is not on the TURN allowlist. Relay access is restricted to protect the shared Cloudflare quota.';
  }
  if (error instanceof TurnPasskeyCancelledError) {
    return 'The direct peer-to-peer connection failed, and passkey approval for TURN relay access was cancelled. Run the command again to retry.';
  }
  if (error instanceof TurnPasskeyUnavailableError) {
    return 'The direct peer-to-peer connection failed, and this browser or passkey could not produce the local identity proof needed for TURN relay access. Check that this passkey supports PRF in this browser, then run the command again to retry.';
  }
  if (error instanceof TurnProviderUnavailableError) {
    return 'The direct peer-to-peer connection failed, and the TURN relay service is temporarily unavailable. Run the command again to retry.';
  }
  return error instanceof ProtocolError && /public key|URL/.test(error.message)
    ? 'This nearby link is invalid. Run the keytap command again and open the fresh approval link.'
    : 'Could not establish the private connection. Check both devices’ network access, then run the command again and open the fresh approval link.';
}

function failBeforeSession(error) {
  if (phase.kind === 'failed') return;
  phase = { kind: 'failed' };
  $('offer').hidden = true;
  $('pairing').hidden = true;
  $('start')?.remove();
  $('title').textContent = 'keytap';
  $('explainer').hidden = true;
  $('details').hidden = true;
  document.title = 'keytap: connection failed';
  alertUser(beforeSessionFailureMessage(error));
  $('alert').focus();
}

export async function main() {
  $('title').textContent = 'Connecting to your CLI';
  $('summary').textContent = 'The public key in this approval link authenticates your CLI while keytap establishes a WebRTC connection.';
  $('explainer').textContent = 'keytap tries a direct peer-to-peer connection first. If that fails, an allowlisted passkey can authorize Cloudflare TURN.';
  $('start').disabled = true;
  $('start').textContent = 'Connecting…';
  say('Waiting for your CLI…');
  const connectingData = { controller: new AbortController() };
  phase = { kind: 'connecting-direct', data: connectingData };

  let session;
  try {
    const cliPublicKey = takeCliPublicKeyFromFragment();
    const verifier = await createCliOfferVerifier(cliPublicKey);
    if (phase.kind !== 'connecting-direct' || phase.data !== connectingData) return;
    const established = await establishPrivateChannel(verifier, connectingData);
    switch (phase.kind) {
      case 'connecting-direct':
      case 'connecting-relay':
        if (phase.data !== connectingData) {
          established.session.close();
          return;
        }
        break;
      default:
        established.session.close();
        return;
    }
    session = established.session;
    phase = { kind: 'awaiting-request', session };
    say('Private connection established. Waiting for the request…');
    const initial = parseInitialRequest(await session.next(SIGNAL_TIMEOUT_MS));
    if (phase.kind !== 'awaiting-request' || phase.session !== session) return;
    switch (initial.kind) {
      case 'pinned':
        configurePinnedRequest(session, initial.request, established.sessionBinding);
        break;
      case 'pairing':
        await startPairing(
          session,
          initial.request,
          established.sessionBinding,
          initial.cliCommitment,
        );
        break;
    }
  } catch (error) {
    if (error instanceof CompletedElsewhereError) {
      const currentPhase = phase;
      const nextPhase = terminateConnectionPhaseForCompletedElsewhere(
        currentPhase,
        connectingData,
      );
      if (nextPhase !== currentPhase) {
        phase = nextPhase;
        renderCompletedElsewhere();
      }
      return;
    }
    if (session) {
      if (phase.kind === 'completed-elsewhere'
          || phase.kind === 'finished'
          || phase.kind === 'failed'
          || phase.kind === 'expired') {
        session.close();
        return;
      }
      failSession(session, error);
      return;
    }
    switch (phase.kind) {
      case 'connecting-direct':
      case 'relay-authorizing':
      case 'connecting-relay':
        if (phase.data !== connectingData) return;
        break;
      case 'relay-consent':
        if (phase.data.connection !== connectingData) return;
        break;
      default:
        return;
    }
    failBeforeSession(error);
  }
}

export function terminatePhaseForPagehide(currentPhase) {
  let session;
  switch (currentPhase.kind) {
    case 'connecting-direct':
    case 'relay-authorizing':
    case 'connecting-relay':
      currentPhase.data.controller.abort();
      return;
    case 'relay-consent':
      currentPhase.data.connection.controller.abort();
      return;
    case 'first-busy':
      currentPhase.data.controller.abort();
      session = currentPhase.data.session;
      break;
    case 'pairing-ceremony':
      currentPhase.data.controller.abort();
      session = currentPhase.data.session;
      try { session.send({ type: 'sas-approver-rejected' }); } catch { /* leaving */ }
      session.close();
      return;
    case 'awaiting-request':
    case 'registration-ack':
      session = currentPhase.session;
      break;
    case 'disposition-choice':
      session = currentPhase.data.session;
      if (currentPhase.data.kind === 'pairing') {
        try { session.send({ type: 'sas-approver-rejected' }); } catch { /* leaving */ }
        session.close();
        return;
      }
      break;
    case 'assertion-ack':
      session = currentPhase.data.session;
      break;
    case 'boot':
    case 'completed-elsewhere':
    case 'finished':
    case 'failed':
    case 'expired':
      return;
  }
  try { session.send({ type: 'done' }); } catch { /* page is leaving */ }
  session.close();
}

export function handlePageShow(event) {
  if (!event.persisted) return;
  const currentPhase = phase;
  phase = { kind: 'expired' };
  terminatePhaseForPagehide(currentPhase);
  document.title = 'keytap: request expired';
  $('title').textContent = 'Request expired';
  $('summary').hidden = true;
  $('explainer').hidden = true;
  $('details').hidden = true;
  $('offer').hidden = true;
  $('pairing').hidden = true;
  $('start')?.remove();
  alertUser('This nearby request expired when you left this page. Run the keytap command again and open the fresh approval link.');
  $('alert').focus();
}

if (typeof document !== 'undefined' && typeof window !== 'undefined') {
  $('start').addEventListener('click', beginRelayAuthorization);
  $('remember-btn').addEventListener('click', () => chooseDisposition('remember'));
  $('done-btn').addEventListener('click', () => chooseDisposition('once'));

  window.addEventListener('pagehide', () => {
    const currentPhase = phase;
    phase = { kind: 'expired' };
    terminatePhaseForPagehide(currentPhase);
  });
  window.addEventListener('pageshow', handlePageShow);
  main();
}
