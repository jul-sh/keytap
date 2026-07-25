import {
  CLOUDFLARE_STUN_ONLY,
  ProtocolError,
  createCliOfferVerifier,
  createNearbyIdentityProof,
  createNearbySessionBinding,
  createSasCommitment,
  createSasContext,
  createSasDigest,
  decodeBase64URL,
  encodeBase64URL,
  filterCloudflareIceServers,
  parseSasWordList,
  requestPairingRelease,
  sasPhrase,
  verifySasCommitment,
} from './nearby-v2-protocol.js';

const RELAY_ORIGIN = 'https://keytap-relay.julsh.workers.dev';
const SIGNAL_OPEN_TIMEOUT_MS = 30_000;
const SIGNAL_TIMEOUT_MS = 120_000;
const ICE_GATHER_TIMEOUT_MS = 45_000;
const DATA_CONNECT_TIMEOUT_MS = 60_000;
const DATA_MESSAGE_TIMEOUT_MS = 120_000;
// The CLI grants 150 seconds once a remember ceremony starts. Keep a small
// transport margin so a retry is never offered after the native deadline.
const REMEMBER_CEREMONY_WINDOW_MS = 140_000;
const MAX_SIGNAL_BYTES = 128 * 1024;
const MAX_DATA_BYTES = 16 * 1024;
const MAX_TURN_RESPONSE_BYTES = 64 * 1024;
const MAX_SAS_WORD_LIST_BYTES = 32 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

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
 * assertion result exists only after an assertion ceremony and a remember
 * offer exists only when the CLI explicitly advertised a live window.
 *
 * @typedef {
 *   {kind: 'boot'} |
 *   {kind: 'connecting', data: ConnectingData} |
 *   {kind: 'awaiting-request', session: DataSession} |
 *   {kind: 'ready', data: ReadyData} |
 *   {kind: 'first-busy', data: FirstBusyData} |
 *   {kind: 'pairing-ceremony', data: PairingCeremonyData} |
 *   {kind: 'pairing-held', data: PairingHeldData} |
 *   {kind: 'registration-ack', session: DataSession} |
 *   {kind: 'assertion-ack', data: AssertionData} |
 *   {kind: 'offer', data: OfferData} |
 *   {kind: 'remember-begin', data: OfferData} |
 *   {kind: 'remember-ceremony', data: RememberCeremonyData} |
 *   {kind: 'remember-ack', data: OfferData} |
 *   {kind: 'finished'} |
 *   {kind: 'failed'}
 * } Phase
 * @typedef {{controller: AbortController}} ConnectingData
 * @typedef {{session: DataSession, request: AssertRequest, sessionBinding: Uint8Array}} ReadyData
 * @typedef {ReadyData & {controller: AbortController}} FirstBusyData
 * @typedef {{session: DataSession, request: AssertRequest, firstResult: FirstResult}} AssertionData
 * @typedef {AssertionData & {expiryAt: number}} OfferData
 * @typedef {OfferData & {controller: AbortController}} RememberCeremonyData
 * @typedef {{credentialId: Uint8Array, prfFirst: Uint8Array, identity: object}} FirstResult
 * @typedef {{session: DataSession, verifier: CliOfferVerifier, sessionBinding: Uint8Array, binding: {kind: 'bootstrap-sas', digest: Uint8Array}}} PairingBaseData
 * @typedef {((PairingBaseData & {kind: 'registration', request: RegisterRequest}) | (PairingBaseData & {kind: 'assertion', request: AssertRequest})) & {controller: AbortController}} PairingCeremonyData
 * @typedef {{session: DataSession, kind: 'registration', credential: PublicKeyCredential, releaseNonce: Uint8Array} | {session: DataSession, kind: 'assertion', result: FirstResult, releaseNonce: Uint8Array}} PairingHeldData
 * @typedef {{verifyPairingRelease: (fields: object) => Promise<void>}} CliOfferVerifier
 * @typedef {{kind: 'register', challenge: Uint8Array, prfSalt: Uint8Array, userId: Uint8Array, userName: string}} RegisterRequest
 * @typedef {{kind: 'assert', challenge: Uint8Array, prfSalt: Uint8Array, identitySalt: Uint8Array, identity: IdentityMode, keyName: string, remember: RememberMode}} AssertRequest
 * @typedef {{kind: 'pairing-any'} | {kind: 'pairing-credential', credentialId: Uint8Array} | {kind: 'pinned', credentialId: Uint8Array}} IdentityMode
 * @typedef {{kind: 'disabled'} | {kind: 'available', windowSecs: number}} RememberMode
 * @typedef {{send: (message: object) => void, next: (timeoutMs?: number) => Promise<object>, close: () => void}} DataSession
 */

/** @type {Phase} */
let phase = { kind: 'boot' };
let expiryTimer = 0;

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
  const values = params.getAll('k');
  // Fragments are never sent in HTTP requests. Remove this one immediately so
  // it also stays out of screenshots, copied URLs, history, and crash reports.
  history.replaceState(null, '', location.pathname + location.search);
  if (values.length !== 1 || [...params.keys()].some(key => key !== 'k')) {
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
  const url = new URL(RELAY_ORIGIN);
  url.protocol = 'wss:';
  url.pathname = `/v2/signal/${encodeURIComponent(rendezvousId)}`;
  url.search = 'role=phone';
  return url.href;
}

async function openSignalSocket(rendezvousId, cancellation) {
  throwIfAborted(cancellation);
  const socket = new WebSocket(signalUrl(rendezvousId));
  const incoming = new AsyncQueue();
  socket.addEventListener('message', event => {
    if (typeof event.data !== 'string' || encoder.encode(event.data).length > MAX_SIGNAL_BYTES) {
      incoming.fail(new ProtocolError('invalid signaling message'));
      return;
    }
    try {
      const message = JSON.parse(event.data);
      if (!message || typeof message !== 'object' || Array.isArray(message)) {
        throw new ProtocolError('invalid signaling message');
      }
      incoming.push(message);
    } catch (error) {
      incoming.fail(error instanceof Error ? error : new ProtocolError('invalid signaling message'));
    }
  });
  socket.addEventListener('close', () => incoming.fail(new ProtocolError('signaling connection closed')));
  socket.addEventListener('error', () => incoming.fail(new ProtocolError('signaling connection failed')));

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
    close() {
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

async function waitForOffer(signal) {
  for (;;) {
    const message = await signal.next(SIGNAL_TIMEOUT_MS);
    if (message.type === 'peer-ready') continue;
    if (message.type === 'error') {
      throw new ProtocolError(typeof message.message === 'string' ? message.message : 'signaling failed');
    }
    return message;
  }
}

async function fetchIceServers(rendezvousId, cancellation) {
  const url = `${RELAY_ORIGIN}/v2/signal/${encodeURIComponent(rendezvousId)}/turn`;
  let response;
  try {
    response = await fetch(url, {
      cache: 'no-store',
      credentials: 'omit',
      headers: { Accept: 'application/json' },
      signal: abortAfter(SIGNAL_OPEN_TIMEOUT_MS, cancellation),
    });
  } catch {
    throw new ProtocolError('could not obtain ICE credentials');
  }
  if (!response.ok) throw new ProtocolError('could not obtain ICE credentials');

  let payload;
  try {
    payload = await readBoundedJson(response, MAX_TURN_RESPONSE_BYTES);
  } catch {
    throw new ProtocolError('invalid TURN response');
  }
  return filterCloudflareIceServers(payload?.iceServers);
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
      reject(new ProtocolError('timed out gathering ICE candidates'));
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
    const timer = setTimeout(() => reject(new ProtocolError('timed out opening the private channel')), DATA_CONNECT_TIMEOUT_MS);

    function rejectOnFailure() {
      if (peer.connectionState === 'failed' || peer.connectionState === 'closed') {
        clearTimeout(timer);
        reject(new ProtocolError('the private connection failed'));
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
      if (channel.label !== 'keytap/3'
          || channel.protocol !== 'keytap.v3'
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
    channel.addEventListener('close', () => reject(new ProtocolError('the private channel closed')), { once: true });
    channel.addEventListener('error', () => reject(new ProtocolError('the private channel failed')), { once: true });
  });
}

function makeDataSession(peer, channel) {
  const incoming = new AsyncQueue();
  let decodeChain = Promise.resolve();
  channel.addEventListener('message', event => {
    decodeChain = decodeChain.then(() => {
      if (typeof event.data !== 'string') throw new ProtocolError('invalid data message');
      if (encoder.encode(event.data).length > MAX_DATA_BYTES) throw new ProtocolError('data message is too large');
      const text = event.data;
      const message = JSON.parse(text);
      if (!message || typeof message !== 'object' || Array.isArray(message)) {
        throw new ProtocolError('invalid data message');
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

  return {
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
}

async function establishPrivateChannel(verifier, cancellation) {
  const signaling = await openSignalSocket(verifier.rendezvousId, cancellation);
  try {
    await abortable(waitForPeer(signaling), cancellation);
    say('Found your CLI. Establishing a private connection…');
    const icePromise = fetchIceServers(verifier.rendezvousId, cancellation).then(
      iceServers => ({ kind: 'turn', iceServers }),
      () => {
        throwIfAborted(cancellation);
        return {
          kind: 'stun-only',
          iceServers: CLOUDFLARE_STUN_ONLY.map(server => ({ urls: [...server.urls] })),
        };
      },
    );
    const offerEnvelope = await abortable(waitForOffer(signaling), cancellation);
    const offerBytes = await abortable(verifier.verifyOffer(offerEnvelope), cancellation);
    if (offerBytes.length === 0 || offerBytes.length > MAX_SIGNAL_BYTES) {
      throw new ProtocolError('invalid authenticated offer');
    }
    const offerSdp = decoder.decode(offerBytes);
    const iceConfiguration = await abortable(icePromise, cancellation);
    if (iceConfiguration.kind === 'stun-only') {
      // TURN minting is an availability aid, not an authentication input.
      // A direct/STUN path may still work when credential generation is down.
      say('TURN is unavailable. Trying a direct connection…');
    }
    const { iceServers } = iceConfiguration;

    if (typeof RTCPeerConnection !== 'function') throw new ProtocolError('WebRTC is unavailable in this browser');
    const peer = new RTCPeerConnection({ iceServers });
    const closePeerOnAbort = () => peer.close();
    cancellation.addEventListener('abort', closePeerOnAbort, { once: true });
    const channelPromise = expectDataChannel(peer).then(
      session => ({ kind: 'open', session }),
      error => ({ kind: 'failed', error }),
    );
    try {
      // The signature check above is the important ordering: no relay-provided SDP,
      // including its DTLS fingerprint, reaches WebRTC before authentication.
      await abortable(peer.setRemoteDescription({ type: 'offer', sdp: offerSdp }), cancellation);
      const answer = await abortable(peer.createAnswer(), cancellation);
      await abortable(peer.setLocalDescription(answer), cancellation);
      await abortable(waitForIceGathering(peer), cancellation);
      const answerSdp = peer.localDescription?.sdp;
      if (typeof answerSdp !== 'string' || answerSdp.length === 0) {
        throw new ProtocolError('could not create a complete WebRTC answer');
      }
      signaling.send({
        v: 3,
        from: 'phone',
        seq: 0,
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
      cancellation.removeEventListener('abort', closePeerOnAbort);
      return { session: channel.session, sessionBinding };
    } catch (error) {
      cancellation.removeEventListener('abort', closePeerOnAbort);
      peer.close();
      throw error;
    }
  } finally {
    signaling.close();
  }
}

function expectObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ProtocolError(`invalid ${label}`);
  }
  return value;
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

function parseRequest(message) {
  expectObject(message, 'request message');
  if (message.type !== 'request' && message.type !== 'pairing-request') {
    throw new ProtocolError('expected a nearby request');
  }
  const request = expectObject(message.request, 'request');
  const challenge = expectBytes(request.challenge, 'challenge', 16, 128);

  if (request.kind === 'register') {
    return {
      kind: 'register',
      challenge,
      prfSalt: expectBytes(request.prfSalt, 'PRF salt', 32, 32),
      userId: expectBytes(request.userId, 'user ID', 1, 64),
      userName: expectString(request.userName, 'user name'),
    };
  }
  if (request.kind !== 'assert') throw new ProtocolError('unsupported nearby request');
  const remember = expectObject(request.remember, 'remember mode');
  let rememberMode;
  if (remember.kind === 'disabled') {
    rememberMode = { kind: 'disabled' };
  } else if (remember.kind === 'available'
      && Number.isInteger(remember.windowSecs)
      && remember.windowSecs > 0
      && remember.windowSecs <= 600) {
    rememberMode = { kind: 'available', windowSecs: remember.windowSecs };
  } else {
    throw new ProtocolError('invalid remember mode');
  }
  const identity = expectObject(request.identity, 'identity mode');
  let identityMode;
  if (identity.kind === 'pairing-any') {
    identityMode = { kind: 'pairing-any' };
  } else if (identity.kind === 'pairing-credential') {
    identityMode = {
      kind: 'pairing-credential',
      credentialId: expectBytes(identity.credentialId, 'pairing credential ID', 1, 1024),
    };
  } else if (identity.kind === 'pinned') {
    identityMode = {
      kind: 'pinned',
      credentialId: expectBytes(identity.credentialId, 'pinned credential ID', 1, 1024),
    };
  } else {
    throw new ProtocolError('invalid identity mode');
  }
  return {
    kind: 'assert',
    challenge,
    prfSalt: expectBytes(request.prfSalt, 'PRF salt', 32, 32),
    identitySalt: expectBytes(request.identitySalt, 'identity PRF salt', 32, 32),
    identity: identityMode,
    keyName: expectString(request.keyName, 'key name'),
    remember: rememberMode,
  };
}

function parseInitialRequest(message) {
  const request = parseRequest(message);
  if (message.type === 'request') {
    if (request.kind !== 'assert' || request.identity.kind !== 'pinned') {
      throw new ProtocolError('an unpaired request cannot skip SAS');
    }
    return { kind: 'pinned', request };
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
  const message = expectObject(await session.next(), 'CLI SAS reveal');
  if (message.type !== 'sas-cli-reveal') {
    throw new ProtocolError('expected CLI SAS reveal');
  }
  return expectBytes(message.nonce, 'CLI pairing nonce', 32, 32);
}

async function startPairing(session, request, sessionBinding, cliCommitment, verifier) {
  const context = await createSasContext(sessionBinding, request);
  if (phase.kind !== 'awaiting-request' || phase.session !== session) return;
  const phoneNonce = crypto.getRandomValues(new Uint8Array(32));
  const phoneCommitment = await createSasCommitment('phone', context, phoneNonce);
  if (phase.kind !== 'awaiting-request' || phase.session !== session) {
    phoneNonce.fill(0);
    return;
  }
  session.send({
    type: 'sas-phone-commit',
    commitment: encodeBase64URL(phoneCommitment),
  });
  const cliNonce = await nextSasCliReveal(session);
  if (phase.kind !== 'awaiting-request' || phase.session !== session) {
    phoneNonce.fill(0);
    cliNonce.fill(0);
    return;
  }
  if (!await verifySasCommitment('cli', context, cliNonce, cliCommitment)) {
    session.send({ type: 'sas-phone-rejected' });
    throw new ProtocolError('the CLI did not open its pairing commitment');
  }
  session.send({
    type: 'sas-phone-reveal',
    nonce: encodeBase64URL(phoneNonce),
  });
  const digest = await createSasDigest(
    context,
    cliCommitment,
    phoneCommitment,
    cliNonce,
    phoneNonce,
  );
  cliNonce.fill(0);
  phoneNonce.fill(0);
  const words = await loadSasWords();
  if (phase.kind !== 'awaiting-request' || phase.session !== session) {
    digest.fill(0);
    return;
  }
  $('pairing-words').textContent = sasPhrase(digest, words);
  $('pairing').hidden = false;
  $('start').hidden = true;
  $('title').textContent = request.kind === 'register'
    ? 'Create your passkey'
    : 'Approve this key request';
  $('summary').textContent = 'Keep these words visible so you can compare them in your terminal afterward.';
  $('explainer').textContent = 'Finish the passkey step on this phone first. Its result stays here until the terminal confirms the words.';
  $('pairing-heading').focus();
  const base = {
    session,
    verifier,
    sessionBinding,
    binding: { kind: 'bootstrap-sas', digest },
  };
  const data = request.kind === 'register'
    ? { ...base, kind: 'registration', request, controller: new AbortController() }
    : { ...base, kind: 'assertion', request, controller: new AbortController() };
  phase = { kind: 'pairing-ceremony', data };
  await runPairingCeremony(data);
}

function discardHeld(data) {
  data.releaseNonce.fill(0);
  if (data.kind === 'assertion') data.result.prfFirst.fill(0);
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
        result: await runInitialAssertion(data.request, data.binding, data.controller.signal),
      };
    }
  } catch (error) {
    if (phase.kind !== 'pairing-ceremony' || phase.data !== data) return;
    try { data.session.send({ type: 'sas-phone-rejected' }); } catch { /* closed */ }
    failSession(data.session, error);
    return;
  }

  if (phase.kind !== 'pairing-ceremony' || phase.data !== data) {
    if (completed.kind === 'assertion') completed.result.prfFirst.fill(0);
    return;
  }
  const releaseNonce = crypto.getRandomValues(new Uint8Array(32));
  const heldData = completed.kind === 'registration'
    ? {
      session: data.session,
      kind: 'registration',
      credential: completed.credential,
      releaseNonce,
    }
    : {
      session: data.session,
      kind: 'assertion',
      result: completed.result,
      releaseNonce,
    };
  phase = { kind: 'pairing-held', data: heldData };
  say('Phone complete. Within two minutes, confirm the same words once in your terminal; you do not need to return here.');
  $('pairing-words').focus();
  try {
    const decision = await requestPairingRelease({
      session: data.session,
      verifier: data.verifier,
      sessionBinding: data.sessionBinding,
      sasDigest: data.binding.digest,
      request: data.request,
      releaseNonce,
    });
    if (phase.kind !== 'pairing-held' || phase.data !== heldData) {
      discardHeld(heldData);
      return;
    }
    if (decision.kind === 'rejected') {
      discardHeld(heldData);
      phase = { kind: 'finished' };
      $('pairing').hidden = true;
      $('title').textContent = 'Pairing rejected';
      $('summary').textContent = 'The terminal did not confirm the pairing words.';
      $('explainer').textContent = 'Run the command again and scan its fresh QR code to retry.';
      alertUser(heldData.kind === 'registration'
        ? 'The terminal rejected the pairing words. A passkey may have been created on this phone, but it was not paired or sent. Run init again for a fresh QR code.'
        : 'The terminal rejected the pairing words. No key or identity was sent or trusted. Run the command again for a fresh QR code.');
      $('alert').focus();
      data.session.close();
      return;
    }

    releaseNonce.fill(0);
    $('pairing').hidden = true;
    if (heldData.kind === 'registration') {
      data.session.send({
        type: 'paired-registration-result',
        credentialId: encodeBase64URL(heldData.credential.rawId),
        releaseSignature: encodeBase64URL(decision.signature),
      });
      phase = { kind: 'registration-ack', session: data.session };
      await nextCliMessage(data.session, 'initial-accepted');
      if (phase.kind !== 'registration-ack' || phase.session !== data.session) return;
      finishRegistration(data.session);
      return;
    }

    sendPairedAssertionResult(data.session, heldData.result, decision.signature);
    const assertionData = {
      session: data.session,
      request: data.request,
      firstResult: heldData.result,
    };
    phase = { kind: 'assertion-ack', data: assertionData };
    await nextCliMessage(data.session, 'initial-accepted');
    if (phase.kind !== 'assertion-ack' || phase.data !== assertionData) return;
    if (data.request.remember.kind === 'available') {
      enterOffer(assertionData, data.request.remember.windowSecs);
    } else {
      finishAssertion(data.session);
    }
  } catch (error) {
    discardHeld(heldData);
    failSession(data.session, error);
  }
}

async function nextCliMessage(session, expectedType) {
  const message = expectObject(await session.next(), 'CLI message');
  if (typeof message.type !== 'string') throw new ProtocolError('invalid CLI message');
  if (message.type === 'protocol-error') {
    const codes = new Set(['invalid-message', 'unexpected-message']);
    if (!codes.has(message.code)) throw new ProtocolError('invalid CLI protocol error');
    throw new ProtocolError(`the CLI rejected the request (${message.code})`);
  }
  if (message.type === 'initial-rejected') {
    const reasons = new Set(['identity-mismatch', 'invalid-identity-proof', 'identity-store-unavailable']);
    if (!reasons.has(message.reason)) throw new ProtocolError('invalid CLI identity rejection');
    throw new InitialRejectionError(message.reason);
  }
  if (message.type === 'initial-indeterminate'
      && message.reason === 'identity-durability-unknown') {
    throw new InitialIndeterminateError(message.reason);
  }
  if (message.type !== expectedType) throw new ProtocolError(`expected ${expectedType}`);
  return message;
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

export function initialRejectionMessage(reason, registration) {
  if (reason === 'identity-store-unavailable') {
    return registration
      ? 'The CLI could not save the trusted identity. A passkey may have been created on this phone, but it was not paired or sent. Run init again.'
      : 'The CLI could not access its trusted identity store, so no key was accepted. Check that machine and run the command again.';
  }
  return 'This passkey did not match the identity already trusted by the CLI, so no key was accepted.';
}

export function initialIndeterminateMessage(registration) {
  return registration
    ? 'Setup status unknown. The CLI received the new passkey but could not confirm that its identity was saved durably. Do not rely on it; check the terminal and rerun keytap init --force. The passkey may remain on this phone.'
    : 'Pairing status unknown. The CLI refused the returned key because it could not confirm that the identity was saved durably. Check the terminal, then retry with a fresh QR code.';
}

export function sessionFailureMessage(error, phaseKind) {
  if (error instanceof InitialRejectionError) {
    return initialRejectionMessage(error.reason, phaseKind === 'registration-ack');
  }
  if (error instanceof InitialIndeterminateError) {
    return initialIndeterminateMessage(phaseKind === 'registration-ack');
  }
  switch (phaseKind) {
    case 'registration-ack':
      return 'The passkey result was sent, but this phone could not confirm whether the CLI saved it. Check the terminal before retrying; a passkey may already have been paired.';
    case 'assertion-ack':
      return 'The key result was sent, but this phone could not confirm whether the CLI accepted it. Check the terminal before retrying.';
    default:
      return 'The private connection failed. Nothing else was sent. Run the command again and scan the fresh code.';
  }
}

async function nextRememberOutcome(session) {
  const message = expectObject(await session.next(), 'CLI message');
  if (typeof message.type !== 'string') throw new ProtocolError('invalid CLI message');
  if (message.type === 'remember-accepted') return { kind: 'accepted' };
  if (message.type === 'remember-rejected' && message.reason === 'mismatch') {
    return { kind: 'rejected', reason: 'mismatch' };
  }
  if (message.type === 'remember-rejected' && message.reason === 'unavailable') {
    return { kind: 'rejected', reason: 'unavailable' };
  }
  if (message.type === 'protocol-error') {
    const codes = new Set(['invalid-message', 'unexpected-message']);
    if (!codes.has(message.code)) throw new ProtocolError('invalid CLI protocol error');
    throw new ProtocolError(`the CLI rejected the request (${message.code})`);
  }
  throw new ProtocolError('expected remember result acknowledgement');
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

async function runInitialAssertion(request, binding, signal) {
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
    }, prfSecondBytes);
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

async function runRememberAssertion(request, allowCredentialId, signal) {
  const publicKey = {
    challenge: request.challenge,
    rpId: 'keytap.jul.sh',
    userVerification: 'required',
    timeout: 120_000,
    extensions: { prf: { eval: { first: request.prfSalt } } },
    allowCredentials: [{ type: 'public-key', id: allowCredentialId }],
  };
  const credential = await navigator.credentials.get({ publicKey, signal });
  const prfFirst = credential?.getClientExtensionResults()?.prf?.results?.first;
  if (!credential?.rawId || !prfFirst) throw new Error('PRF output was not returned.');
  return {
    credentialId: new Uint8Array(credential.rawId),
    prfFirst: new Uint8Array(prfFirst),
  };
}

function sendAssertionResult(session, result) {
  try {
    session.send({
      type: 'assertion-result',
      credentialId: encodeBase64URL(result.credentialId),
      prfFirst: encodeBase64URL(result.prfFirst),
      identity: result.identity,
    });
  } finally {
    result.prfFirst.fill(0);
  }
}

function sendPairedAssertionResult(session, result, releaseSignature) {
  try {
    session.send({
      type: 'paired-assertion-result',
      credentialId: encodeBase64URL(result.credentialId),
      prfFirst: encodeBase64URL(result.prfFirst),
      identity: result.identity,
      releaseSignature: encodeBase64URL(releaseSignature),
    });
  } finally {
    result.prfFirst.fill(0);
  }
}

function isCancel(error) {
  return error && (error.name === 'NotAllowedError' || error.name === 'AbortError');
}

function configurePinnedRequest(session, request, sessionBinding) {
  $('offer').hidden = true;
  $('pairing').hidden = true;
  const button = $('start');
  button.disabled = false;
  button.setAttribute('aria-disabled', 'false');
  $('title').textContent = 'Approve this key request';
  render($('summary'), 'Your CLI requested key: ', { code: request.keyName });
  $('explainer').textContent = 'Approve with this device to send the derived key over the encrypted peer connection.';
  button.textContent = 'Approve request';
  say('Ready.');
  phase = { kind: 'ready', data: { session, request, sessionBinding } };
  runFirst();
}

async function runFirst() {
  if (phase.kind !== 'ready') return;
  const readyData = phase.data;
  const data = { ...readyData, controller: new AbortController() };
  phase = { kind: 'first-busy', data };
  const button = $('start');
  button.disabled = true;
  button.setAttribute('aria-disabled', 'true');
  document.title = 'keytap: approve';

  say('Waiting for passkey approval…');
  let firstResult;
  try {
    firstResult = await runInitialAssertion(data.request, {
      kind: 'pinned-session',
      digest: data.sessionBinding,
    }, data.controller.signal);
  } catch (error) {
    restoreAfterCeremonyError(data, button, error);
    return;
  }
  if (phase.kind !== 'first-busy' || phase.data !== data) {
    firstResult.prfFirst.fill(0);
    return;
  }
  try {
    sendAssertionResult(data.session, firstResult);
    const assertionData = { session: data.session, request: data.request, firstResult };
    phase = { kind: 'assertion-ack', data: assertionData };
    await nextCliMessage(data.session, 'initial-accepted');
    if (phase.kind !== 'assertion-ack' || phase.data !== assertionData) return;
    if (data.request.remember.kind === 'available') {
      enterOffer(assertionData, data.request.remember.windowSecs);
    } else {
      finishAssertion(data.session);
    }
  } catch (error) {
    failSession(data.session, error);
  }
}

function restoreAfterCeremonyError(data, button, error) {
  if (phase.kind !== 'first-busy' || phase.data !== data) return;
  const readyData = {
    session: data.session,
    request: data.request,
    sessionBinding: data.sessionBinding,
  };
  phase = { kind: 'ready', data: readyData };
  button.disabled = false;
  button.setAttribute('aria-disabled', 'false');
  document.title = 'keytap';
  const label = data.request.kind === 'register' ? 'Create passkey' : 'Approve request';
  if (isCancel(error)) {
    say(`The passkey prompt was cancelled or didn’t open. Nothing was sent. Tap ${label} to try again.`);
  } else {
    console.error(error);
    const detail = error instanceof Error && error.message
      ? error.message
      : 'The passkey ceremony failed.';
    alertUser(detail);
  }
}

function finishRegistration(session) {
  clearTimeout(expiryTimer);
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

function finishAssertion(session) {
  clearTimeout(expiryTimer);
  phase = { kind: 'finished' };
  document.title = 'keytap: sent';
  $('title').textContent = 'Key sent';
  $('summary').hidden = true;
  $('explainer').hidden = true;
  $('details').hidden = true;
  $('start')?.remove();
  $('offer').hidden = true;
  $('pairing').hidden = true;
  say('Sent. Your CLI has the key. You can close this page.');
  $('status').focus();
  setTimeout(() => session.close(), 750);
}

function humanDuration(seconds) {
  return seconds < 90 ? `about ${seconds} seconds` : `about ${Math.round(seconds / 60)} minutes`;
}

function setOfferButtonsDisabled(disabled) {
  for (const button of [$('remember-btn'), $('done-btn')]) {
    button.disabled = disabled;
    button.setAttribute('aria-disabled', disabled ? 'true' : 'false');
  }
}

function enterOffer(assertionData, windowSecs) {
  $('summary').hidden = true;
  $('explainer').hidden = true;
  $('details').hidden = true;
  $('start')?.remove();
  render(
    $('offer-body'),
    'That machine can keep ', { code: assertionData.request.keyName },
    ', so keytap stops prompting for it until ',
    { code: `keytap forget ${assertionData.request.keyName}` },
    '. Confirming takes one more passkey check.',
  );
  $('offer-hint').textContent = `This offer ends when that machine stops waiting, in ${humanDuration(windowSecs)}. Don’t remember stores nothing.`;
  $('offer').hidden = false;
  setOfferButtonsDisabled(false);
  say('Sent. Your CLI has the key.');
  $('offer-heading').focus();
  const data = { ...assertionData, expiryAt: Date.now() + Math.max(windowSecs - 2, 1) * 1000 };
  phase = { kind: 'offer', data };
  scheduleExpiry();
}

function scheduleExpiry() {
  if (phase.kind !== 'offer') return;
  clearTimeout(expiryTimer);
  const delay = Math.max(phase.data.expiryAt - Date.now(), 0);
  expiryTimer = setTimeout(expireOffer, delay + 20);
}

function expireOffer() {
  if (phase.kind !== 'offer') return;
  const { session, request } = phase.data;
  try { session.send({ type: 'done' }); } catch { /* the CLI already left */ }
  phase = { kind: 'finished' };
  $('offer').hidden = true;
  document.title = 'keytap: finished';
  alertUser(
    'That machine has finished waiting, so this page can no longer set it up. Nothing was stored. To remember ',
    { code: request.keyName }, ' there, run ', { code: `keytap remember ${request.keyName}` }, ' in that terminal.',
  );
  $('alert').focus();
  setTimeout(() => session.close(), 750);
}

async function onRemember() {
  if (phase.kind !== 'offer') return;
  const beginData = phase.data;
  clearTimeout(expiryTimer);
  setOfferButtonsDisabled(true);
  phase = { kind: 'remember-begin', data: beginData };
  say('Checking that your CLI is still waiting…');
  try {
    beginData.session.send({ type: 'remember-begin' });
    await nextCliMessage(beginData.session, 'remember-ready');
    if (phase.kind !== 'remember-begin' || phase.data !== beginData) return;
    const ceremonyData = {
      ...beginData,
      expiryAt: Date.now() + REMEMBER_CEREMONY_WINDOW_MS,
      controller: new AbortController(),
    };
    phase = { kind: 'remember-ceremony', data: ceremonyData };
    say('Confirming with your passkey…');
    document.title = 'keytap: approve';
    const result = await runRememberAssertion(
      ceremonyData.request,
      ceremonyData.firstResult.credentialId,
      ceremonyData.controller.signal,
    );
    if (phase.kind !== 'remember-ceremony' || phase.data !== ceremonyData) {
      result.prfFirst.fill(0);
      return;
    }
    try {
      ceremonyData.session.send({
        type: 'remember-result',
        credentialId: encodeBase64URL(result.credentialId),
        prfFirst: encodeBase64URL(result.prfFirst),
      });
    } finally {
      result.prfFirst.fill(0);
    }
    const ackData = {
      session: ceremonyData.session,
      request: ceremonyData.request,
      firstResult: ceremonyData.firstResult,
      expiryAt: ceremonyData.expiryAt,
    };
    phase = { kind: 'remember-ack', data: ackData };
    const outcome = await nextRememberOutcome(ackData.session);
    if (phase.kind !== 'remember-ack' || phase.data !== ackData) return;
    if (outcome.kind === 'rejected') {
      if (outcome.reason === 'unavailable') {
        phase = { kind: 'finished' };
        $('offer').hidden = true;
        document.title = 'keytap: sent';
        alertUser('The key was sent, but the CLI could not access its secure storage, so nothing was remembered. Check that machine before trying again.');
        $('alert').focus();
        setTimeout(() => ackData.session.close(), 750);
        return;
      }
      if (Date.now() >= ackData.expiryAt) {
        phase = { kind: 'offer', data: ackData };
        expireOffer();
        return;
      }
      phase = { kind: 'offer', data: ackData };
      setOfferButtonsDisabled(false);
      document.title = 'keytap: sent';
      alertUser('That approval used a different passkey, so nothing was stored. Try again with the passkey that derived the key.');
      $('remember-btn').focus();
      scheduleExpiry();
      return;
    }
    phase = { kind: 'finished' };
    $('offer').hidden = true;
    document.title = 'keytap: remembered';
    say('Remembered. The terminal confirms where the key was stored. You can close this page.');
    $('status').focus();
    setTimeout(() => ackData.session.close(), 750);
  } catch (error) {
    if (phase.kind === 'finished' || phase.kind === 'failed') return;
    if (isCancel(error) && phase.kind === 'remember-ceremony') {
      const { session } = phase.data;
      try { session.send({ type: 'done' }); } catch { /* already closed */ }
      phase = { kind: 'finished' };
      $('offer').hidden = true;
      document.title = 'keytap: sent';
      say('Passkey check cancelled. The key was already sent; nothing was stored. You can close this page.');
      $('status').focus();
      setTimeout(() => session.close(), 750);
      return;
    }
    failSession(beginData.session, error);
  }
}

function onDone() {
  if (phase.kind !== 'offer') return;
  const { session } = phase.data;
  clearTimeout(expiryTimer);
  phase = { kind: 'finished' };
  setOfferButtonsDisabled(true);
  try { session.send({ type: 'done' }); } catch { /* the CLI already left */ }
  $('offer').hidden = true;
  document.title = 'keytap: finished';
  say('Done. You can close this page.');
  $('status').focus();
  setTimeout(() => session.close(), 750);
}

function failSession(session, error) {
  if (phase.kind === 'failed' || phase.kind === 'finished') return;
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
  const message = error instanceof ProtocolError && /public key|URL/.test(error.message)
    ? 'This nearby link is invalid. Run the keytap command again and scan the fresh code.'
    : 'Could not establish the private connection. Check both devices’ network access, then run the command again and scan the fresh code.';
  alertUser(message);
  $('alert').focus();
}

export async function main() {
  $('title').textContent = 'Connecting to your CLI';
  $('summary').textContent = 'The public key in the QR authenticates your CLI while keytap establishes a WebRTC connection.';
  $('explainer').textContent = 'Cloudflare may route the connection with TURN when a direct path is unavailable.';
  $('start').disabled = true;
  $('start').textContent = 'Connecting…';
  say('Waiting for your CLI…');
  const connectingData = { controller: new AbortController() };
  phase = { kind: 'connecting', data: connectingData };

  let session;
  try {
    const cliPublicKey = takeCliPublicKeyFromFragment();
    const verifier = await createCliOfferVerifier(cliPublicKey);
    if (phase.kind !== 'connecting' || phase.data !== connectingData) return;
    const established = await establishPrivateChannel(verifier, connectingData.controller.signal);
    if (phase.kind !== 'connecting' || phase.data !== connectingData) {
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
          verifier,
        );
        break;
    }
  } catch (error) {
    if (session) {
      if (phase.kind === 'finished' || phase.kind === 'failed') {
        session.close();
        return;
      }
      failSession(session, error);
      return;
    }
    if (phase.kind !== 'connecting' || phase.data !== connectingData) {
      return;
    }
    failBeforeSession(error);
  }
}

export function terminatePhaseForPagehide(currentPhase) {
  let session;
  switch (currentPhase.kind) {
    case 'connecting':
      currentPhase.data.controller.abort();
      return;
    case 'first-busy':
      currentPhase.data.controller.abort();
      session = currentPhase.data.session;
      break;
    case 'pairing-ceremony':
      currentPhase.data.controller.abort();
      session = currentPhase.data.session;
      try { session.send({ type: 'sas-phone-rejected' }); } catch { /* leaving */ }
      session.close();
      return;
    case 'pairing-held':
      session = currentPhase.data.session;
      discardHeld(currentPhase.data);
      try { session.send({ type: 'sas-phone-rejected' }); } catch { /* leaving */ }
      session.close();
      return;
    case 'remember-ceremony':
      currentPhase.data.controller.abort();
      session = currentPhase.data.session;
      break;
    case 'awaiting-request':
    case 'registration-ack':
      session = currentPhase.session;
      break;
    case 'ready':
    case 'assertion-ack':
    case 'offer':
    case 'remember-begin':
    case 'remember-ack':
      session = currentPhase.data.session;
      break;
    case 'boot':
    case 'finished':
    case 'failed':
      return;
  }
  try { session.send({ type: 'done' }); } catch { /* page is leaving */ }
  session.close();
}

if (typeof document !== 'undefined' && typeof window !== 'undefined') {
  $('start').addEventListener('click', runFirst);
  $('remember-btn').addEventListener('click', onRemember);
  $('done-btn').addEventListener('click', onDone);

  window.addEventListener('pagehide', () => {
    const currentPhase = phase;
    phase = { kind: 'finished' };
    terminatePhaseForPagehide(currentPhase);
  });

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && phase.kind === 'offer') scheduleExpiry();
  });
}
