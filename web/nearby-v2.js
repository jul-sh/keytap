import {
  CLOUDFLARE_STUN_ONLY,
  ProtocolError,
  createNearbyIdentityProof,
  createNearbySessionBinding,
  createSignalAuthenticator,
  decodeBase64URL,
  encodeBase64URL,
  filterCloudflareIceServers,
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
 *   {kind: 'connecting'} |
 *   {kind: 'ready', data: ReadyData} |
 *   {kind: 'first-busy', data: ReadyData} |
 *   {kind: 'registration-ack', session: DataSession} |
 *   {kind: 'assertion-ack', data: AssertionData} |
 *   {kind: 'offer', data: OfferData} |
 *   {kind: 'remember-begin', data: OfferData} |
 *   {kind: 'remember-ceremony', data: OfferData} |
 *   {kind: 'remember-ack', data: OfferData} |
 *   {kind: 'finished'} |
 *   {kind: 'failed'}
 * } Phase
 * @typedef {{session: DataSession, request: NearbyRequest, sessionBinding: Uint8Array}} ReadyData
 * @typedef {{session: DataSession, request: AssertRequest, firstResult: FirstResult}} AssertionData
 * @typedef {AssertionData & {expiryAt: number}} OfferData
 * @typedef {{credentialId: Uint8Array, credentialIdB64: string, prfFirstB64: string}} FirstResult
 * @typedef {
 *   {kind: 'register', challenge: Uint8Array, prfSalt: Uint8Array, userId: Uint8Array, userName: string} |
 *   AssertRequest
 * } NearbyRequest
 * @typedef {{kind: 'assert', challenge: Uint8Array, prfSalt: Uint8Array, identitySalt: Uint8Array, identity: IdentityMode, keyName: string, remember: RememberMode}} AssertRequest
 * @typedef {{kind: 'tofu'} | {kind: 'pinned', credentialId: Uint8Array}} IdentityMode
 * @typedef {{kind: 'disabled'} | {kind: 'available', windowSecs: number}} RememberMode
 * @typedef {{send: (message: object) => void, next: (timeoutMs?: number) => Promise<object>, close: () => void, isOpen: () => boolean}} DataSession
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

function abortAfter(ms) {
  if (typeof AbortSignal.timeout === 'function') return AbortSignal.timeout(ms);
  const controller = new AbortController();
  setTimeout(() => controller.abort(), ms);
  return controller.signal;
}

function takeCapabilityFromFragment() {
  const hash = location.hash.startsWith('#') ? location.hash.slice(1) : '';
  const params = new URLSearchParams(hash);
  const values = params.getAll('q');
  // Fragments are never sent in HTTP requests. Remove this one immediately so
  // it also stays out of screenshots, copied URLs, history, and crash reports.
  history.replaceState(null, '', location.pathname + location.search);
  if (values.length !== 1) throw new ProtocolError('No nearby capability in URL.');
  let capability;
  try {
    capability = decodeBase64URL(values[0]);
  } catch {
    throw new ProtocolError('Invalid nearby capability.');
  }
  if (capability.length !== 32) throw new ProtocolError('Invalid nearby capability.');
  return capability;
}

function signalUrl(rendezvousId) {
  const url = new URL(RELAY_ORIGIN);
  url.protocol = 'wss:';
  url.pathname = `/v2/signal/${encodeURIComponent(rendezvousId)}`;
  url.search = 'role=phone';
  return url.href;
}

async function openSignalSocket(rendezvousId) {
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

  await new Promise((resolve, reject) => {
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
  });

  return {
    next: timeoutMs => incoming.next(timeoutMs),
    send(message) {
      if (socket.readyState !== WebSocket.OPEN) throw new ProtocolError('signaling connection closed');
      const encoded = JSON.stringify(message);
      if (encoder.encode(encoded).length > MAX_SIGNAL_BYTES) throw new ProtocolError('signaling message is too large');
      socket.send(encoded);
    },
    close() {
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

async function fetchIceServers(rendezvousId) {
  const url = `${RELAY_ORIGIN}/v2/signal/${encodeURIComponent(rendezvousId)}/turn/phone`;
  let response;
  try {
    response = await fetch(url, {
      cache: 'no-store',
      credentials: 'omit',
      headers: { Accept: 'application/json' },
      signal: abortAfter(SIGNAL_OPEN_TIMEOUT_MS),
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
  const rawServers = Array.isArray(payload?.iceServers)
    ? payload.iceServers
    : payload?.result?.iceServers;
  return filterCloudflareIceServers(rawServers);
}

async function readBoundedJson(response, maximumBytes) {
  const declaredLength = Number(response.headers.get('Content-Length'));
  if (Number.isFinite(declaredLength) && declaredLength > maximumBytes) {
    throw new ProtocolError('response is too large');
  }
  if (!response.body?.getReader) {
    const text = await response.text();
    if (encoder.encode(text).length > maximumBytes) throw new ProtocolError('response is too large');
    return JSON.parse(text);
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
  return JSON.parse(decoder.decode(bytes));
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
      if (channel.label !== 'keytap/2'
          || channel.protocol !== 'keytap.v2'
          || !channel.ordered
          || channel.maxRetransmits !== null
          || channel.maxPacketLifeTime !== null) {
        clearTimeout(timer);
        channel.close();
        reject(new ProtocolError('the CLI opened an invalid data channel'));
        return;
      }
      channel.binaryType = 'arraybuffer';
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
    decodeChain = decodeChain.then(async () => {
      let text;
      if (typeof event.data === 'string') {
        if (encoder.encode(event.data).length > MAX_DATA_BYTES) throw new ProtocolError('data message is too large');
        text = event.data;
      } else if (event.data instanceof ArrayBuffer) {
        if (event.data.byteLength > MAX_DATA_BYTES) throw new ProtocolError('data message is too large');
        text = decoder.decode(event.data);
      } else if (event.data instanceof Blob) {
        if (event.data.size > MAX_DATA_BYTES) throw new ProtocolError('data message is too large');
        text = decoder.decode(await event.data.arrayBuffer());
      } else {
        throw new ProtocolError('invalid data message');
      }
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
    isOpen() {
      return channel.readyState === 'open';
    },
  };
}

async function establishPrivateChannel(authenticator) {
  const signal = await openSignalSocket(authenticator.rendezvousId);
  try {
    await waitForPeer(signal);
    say('Found your CLI. Establishing a private connection…');
    const icePromise = fetchIceServers(authenticator.rendezvousId).then(
      iceServers => ({ kind: 'turn', iceServers }),
      () => ({
        kind: 'stun-only',
        iceServers: CLOUDFLARE_STUN_ONLY.map(server => ({ urls: [...server.urls] })),
      }),
    );
    const offerEnvelope = await waitForOffer(signal);
    const offerBytes = await authenticator.verify(offerEnvelope, 'cli', 0, 'offer');
    if (offerBytes.length === 0 || offerBytes.length > MAX_SIGNAL_BYTES) {
      throw new ProtocolError('invalid authenticated offer');
    }
    const offerSdp = decoder.decode(offerBytes);
    const iceConfiguration = await icePromise;
    if (iceConfiguration.kind === 'stun-only') {
      // TURN minting is an availability aid, not an authentication input.
      // A direct/STUN path may still work when credential generation is down.
      say('TURN is unavailable. Trying a direct connection…');
    }
    const { iceServers } = iceConfiguration;

    if (typeof RTCPeerConnection !== 'function') throw new ProtocolError('WebRTC is unavailable in this browser');
    const peer = new RTCPeerConnection({ iceServers });
    const channelPromise = expectDataChannel(peer).then(
      session => ({ kind: 'open', session }),
      error => ({ kind: 'failed', error }),
    );
    try {
      // The HMAC check above is the important ordering: no relay-provided SDP,
      // including its DTLS fingerprint, reaches WebRTC before authentication.
      await peer.setRemoteDescription({ type: 'offer', sdp: offerSdp });
      const answer = await peer.createAnswer();
      await peer.setLocalDescription(answer);
      await waitForIceGathering(peer);
      const answerSdp = peer.localDescription?.sdp;
      if (typeof answerSdp !== 'string' || answerSdp.length === 0) {
        throw new ProtocolError('could not create a complete WebRTC answer');
      }
      const envelope = await authenticator.sign('phone', 0, 'answer', answerSdp);
      signal.send(envelope);
      const channel = await channelPromise;
      if (channel.kind === 'failed') throw channel.error;
      const sessionBinding = await createNearbySessionBinding(
        authenticator.capabilityBinding,
        offerBytes,
        encoder.encode(answerSdp),
      );
      return { session: channel.session, sessionBinding };
    } catch (error) {
      peer.close();
      throw error;
    }
  } finally {
    signal.close();
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
  if (message.v !== 2 || message.type !== 'request') throw new ProtocolError('expected a v2 request');
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
  if (identity.kind === 'tofu') {
    identityMode = { kind: 'tofu' };
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

async function nextCliMessage(session, expectedType) {
  const message = expectObject(await session.next(), 'CLI message');
  if (message.v !== 2 || typeof message.type !== 'string') throw new ProtocolError('invalid CLI message');
  if (message.type === 'protocol-error') {
    const codes = new Set(['invalid-message', 'unexpected-message', 'remember-mismatch']);
    if (!codes.has(message.code)) throw new ProtocolError('invalid CLI protocol error');
    throw new ProtocolError(`the CLI rejected the request (${message.code})`);
  }
  if (message.type === 'initial-rejected') {
    const reasons = new Set(['identity-mismatch', 'invalid-identity-proof', 'identity-store-unavailable']);
    if (!reasons.has(message.reason)) throw new ProtocolError('invalid CLI identity rejection');
    throw new ProtocolError(`the CLI rejected the passkey identity (${message.reason})`);
  }
  if (message.type !== expectedType) throw new ProtocolError(`expected ${expectedType}`);
  return message;
}

async function nextRememberOutcome(session) {
  const message = expectObject(await session.next(), 'CLI message');
  if (message.v !== 2 || typeof message.type !== 'string') throw new ProtocolError('invalid CLI message');
  if (message.type === 'remember-accepted') return { kind: 'accepted' };
  if (message.type === 'remember-rejected' && message.reason === 'mismatch') {
    return { kind: 'rejected', reason: 'mismatch' };
  }
  if (message.type === 'protocol-error') {
    const codes = new Set(['invalid-message', 'unexpected-message', 'remember-mismatch']);
    if (!codes.has(message.code)) throw new ProtocolError('invalid CLI protocol error');
    throw new ProtocolError(`the CLI rejected the request (${message.code})`);
  }
  throw new ProtocolError('expected remember result acknowledgement');
}

function runRegister(request) {
  return navigator.credentials.create({
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

async function runInitialAssertion(request, sessionBinding) {
  const publicKey = {
    challenge: request.challenge,
    rpId: 'keytap.jul.sh',
    userVerification: 'required',
    timeout: 120_000,
    extensions: {
      prf: { eval: { first: request.prfSalt, second: request.identitySalt } },
    },
  };
  if (request.identity.kind === 'pinned') {
    publicKey.allowCredentials = [{ type: 'public-key', id: request.identity.credentialId }];
  }
  const credential = await navigator.credentials.get({ publicKey });
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
      sessionBinding,
      challenge: request.challenge,
      credentialId,
      prfFirst: prfFirstBytes,
      keyName: request.keyName,
    }, prfSecondBytes);
  } finally {
    prfSecondBytes.fill(0);
  }
  return {
    credentialId,
    credentialIdB64: encodeBase64URL(credential.rawId),
    prfFirstB64: encodeBase64URL(prfFirst),
    identity: {
      algorithm: 'ed25519',
      publicKey: encodeBase64URL(identity.publicKey),
      signature: encodeBase64URL(identity.signature),
    },
  };
}

async function runRememberAssertion(request, allowCredentialId) {
  const publicKey = {
    challenge: request.challenge,
    rpId: 'keytap.jul.sh',
    userVerification: 'required',
    timeout: 120_000,
    extensions: { prf: { eval: { first: request.prfSalt } } },
    allowCredentials: [{ type: 'public-key', id: allowCredentialId }],
  };
  const credential = await navigator.credentials.get({ publicKey });
  const prfFirst = credential?.getClientExtensionResults()?.prf?.results?.first;
  if (!credential?.rawId || !prfFirst) throw new Error('PRF output was not returned.');
  return {
    credentialId: new Uint8Array(credential.rawId),
    credentialIdB64: encodeBase64URL(credential.rawId),
    prfFirstB64: encodeBase64URL(prfFirst),
  };
}

function isCancel(error) {
  return error && (error.name === 'NotAllowedError' || error.name === 'AbortError');
}

function configureForRequest(session, request, sessionBinding) {
  $('offer').hidden = true;
  const button = $('start');
  button.disabled = false;
  button.setAttribute('aria-disabled', 'false');
  if (request.kind === 'register') {
    $('title').textContent = 'Create your keytap passkey';
    $('summary').textContent = 'Create the passkey once, then keytap can recover the same keys anywhere.';
    $('explainer').textContent = 'No account is needed. Your passkey stays in your password manager.';
    button.textContent = 'Create passkey';
  } else {
    $('title').textContent = 'Approve this key request';
    render($('summary'), 'Your CLI requested key: ', { code: request.keyName });
    $('explainer').textContent = 'Approve with this device to send the derived key over the encrypted peer connection.';
    button.textContent = 'Approve request';
  }
  say('Ready.');
  phase = { kind: 'ready', data: { session, request, sessionBinding } };
  if (request.kind === 'assert') runFirst();
}

function renderSecurityModel() {
  const paragraph = $('details').querySelector('p');
  paragraph.textContent = 'The QR code authenticates the complete WebRTC setup. On first use, the CLI remembers a public identity derived from this passkey; later results must carry a fresh signature from that same identity. Cloudflare signaling and TURN can route or block the connection, but cannot read the encrypted DataChannel. First use still trusts whoever scans the QR first, and this webpage remains trusted. Remembering a key requires a second approval.';
}

async function runFirst() {
  if (phase.kind !== 'ready') return;
  const data = phase.data;
  phase = { kind: 'first-busy', data };
  const button = $('start');
  button.disabled = true;
  button.setAttribute('aria-disabled', 'true');
  document.title = 'keytap: approve';

  if (data.request.kind === 'register') {
    say('Waiting for passkey creation…');
    let credential;
    try {
      credential = await runRegister(data.request);
    } catch (error) {
      restoreAfterCeremonyError(data, button, error);
      return;
    }
    try {
      data.session.send({
        v: 2,
        type: 'registration-result',
        credentialId: encodeBase64URL(credential.rawId),
      });
      phase = { kind: 'registration-ack', session: data.session };
      await nextCliMessage(data.session, 'initial-accepted');
      finishRegistration(data.session);
    } catch (error) {
      failSession(data.session, error);
    }
    return;
  }

  say('Waiting for passkey approval…');
  let firstResult;
  try {
    firstResult = await runInitialAssertion(data.request, data.sessionBinding);
  } catch (error) {
    restoreAfterCeremonyError(data, button, error);
    return;
  }
  try {
    data.session.send({
      v: 2,
      type: 'assertion-result',
      credentialId: firstResult.credentialIdB64,
      prfFirst: firstResult.prfFirstB64,
      identity: firstResult.identity,
    });
    const assertionData = { session: data.session, request: data.request, firstResult };
    phase = { kind: 'assertion-ack', data: assertionData };
    await nextCliMessage(data.session, 'initial-accepted');
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
  if (phase.kind !== 'first-busy') return;
  phase = { kind: 'ready', data };
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
  try { session.send({ v: 2, type: 'done' }); } catch { /* the CLI already left */ }
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
  const data = phase.data;
  clearTimeout(expiryTimer);
  setOfferButtonsDisabled(true);
  phase = { kind: 'remember-begin', data };
  say('Checking that your CLI is still waiting…');
  try {
    data.session.send({ v: 2, type: 'remember-begin' });
    await nextCliMessage(data.session, 'remember-ready');
    data.expiryAt = Date.now() + REMEMBER_CEREMONY_WINDOW_MS;
    phase = { kind: 'remember-ceremony', data };
    say('Confirming with your passkey…');
    document.title = 'keytap: approve';
    const result = await runRememberAssertion(data.request, data.firstResult.credentialId);
    data.session.send({
      v: 2,
      type: 'remember-result',
      credentialId: result.credentialIdB64,
      prfFirst: result.prfFirstB64,
    });
    phase = { kind: 'remember-ack', data };
    const outcome = await nextRememberOutcome(data.session);
    if (outcome.kind === 'rejected') {
      if (Date.now() >= data.expiryAt) {
        phase = { kind: 'offer', data };
        expireOffer();
        return;
      }
      phase = { kind: 'offer', data };
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
    setTimeout(() => data.session.close(), 750);
  } catch (error) {
    if (isCancel(error) && phase.kind === 'remember-ceremony') {
      try { data.session.send({ v: 2, type: 'done' }); } catch { /* already closed */ }
      phase = { kind: 'finished' };
      $('offer').hidden = true;
      document.title = 'keytap: sent';
      say('Passkey check cancelled. The key was already sent; nothing was stored. You can close this page.');
      $('status').focus();
      setTimeout(() => data.session.close(), 750);
      return;
    }
    failSession(data.session, error);
  }
}

function onDone() {
  if (phase.kind !== 'offer') return;
  const { session } = phase.data;
  clearTimeout(expiryTimer);
  phase = { kind: 'finished' };
  setOfferButtonsDisabled(true);
  try { session.send({ v: 2, type: 'done' }); } catch { /* the CLI already left */ }
  $('offer').hidden = true;
  document.title = 'keytap: finished';
  say('Done. You can close this page.');
  $('status').focus();
  setTimeout(() => session.close(), 750);
}

function failSession(session, error) {
  if (phase.kind === 'failed' || phase.kind === 'finished') return;
  session.close();
  phase = { kind: 'failed' };
  $('offer').hidden = true;
  $('start')?.remove();
  document.title = 'keytap: connection failed';
  const identityFailure = error instanceof ProtocolError && /identity/.test(error.message);
  alertUser(identityFailure
    ? 'This passkey did not match the identity already trusted by the CLI, so no key was accepted.'
    : 'The private connection failed. Nothing else was sent. Run the command again and scan the fresh code.');
  $('alert').focus();
}

function failBeforeSession(error) {
  if (phase.kind === 'failed') return;
  phase = { kind: 'failed' };
  $('offer').hidden = true;
  $('start')?.remove();
  $('title').textContent = 'keytap';
  $('explainer').hidden = true;
  $('details').hidden = true;
  document.title = 'keytap: connection failed';
  const message = error instanceof ProtocolError && /capability|URL/.test(error.message)
    ? 'This nearby link is invalid. Run the keytap command again and scan the fresh code.'
    : 'Could not establish the private connection. Check both devices’ network access, then run the command again and scan the fresh code.';
  alertUser(message);
  $('alert').focus();
}

function sessionForPagehide() {
  switch (phase.kind) {
    case 'ready':
    case 'first-busy':
      return null;
    case 'registration-ack':
      return phase.session;
    case 'assertion-ack':
    case 'offer':
    case 'remember-begin':
      return phase.data.session;
    case 'remember-ceremony':
    case 'remember-ack':
    case 'boot':
    case 'connecting':
    case 'finished':
    case 'failed':
      return null;
  }
}

export async function main() {
  renderSecurityModel();
  $('title').textContent = 'Connecting to your CLI';
  $('summary').textContent = 'The QR capability stays on this device while keytap establishes an authenticated WebRTC connection.';
  $('explainer').textContent = 'Cloudflare may route the connection with TURN when a direct path is unavailable.';
  $('start').disabled = true;
  $('start').textContent = 'Connecting…';
  say('Waiting for your CLI…');
  phase = { kind: 'connecting' };

  let session;
  try {
    const capability = takeCapabilityFromFragment();
    const authenticator = await createSignalAuthenticator(capability);
    const established = await establishPrivateChannel(authenticator);
    session = established.session;
    say('Private connection established. Waiting for the request…');
    const request = parseRequest(await session.next(SIGNAL_TIMEOUT_MS));
    configureForRequest(session, request, established.sessionBinding);
  } catch (error) {
    if (session) failSession(session, error);
    else failBeforeSession(error);
  }
}

$('start').addEventListener('click', runFirst);
$('remember-btn').addEventListener('click', onRemember);
$('done-btn').addEventListener('click', onDone);

window.addEventListener('pagehide', () => {
  const session = sessionForPagehide();
  if (!session?.isOpen()) return;
  try { session.send({ v: 2, type: 'done' }); } catch { /* page is leaving */ }
});

document.addEventListener('visibilitychange', () => {
  if (!document.hidden && phase.kind === 'offer') scheduleExpiry();
});
