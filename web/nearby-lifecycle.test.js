import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import test from 'node:test';

import {
  CompletedElsewhereError,
  PeerConnectionEstablishmentError,
  TurnPasskeyCancelledError,
  TurnPasskeyNotAllowlistedError,
  TurnPasskeyUnavailableError,
  TurnProviderUnavailableError,
  authorizeTurnWithPasskey as authorizeTurnWithPasskeyRuntime,
  beforeSessionFailureMessage,
  fetchTurnIceServers,
  fetchTurnPasskeyChallenge,
  handlePageShow,
  initialIndeterminateMessage,
  initialRejectionMessage,
  makeDataSession,
  openSignalSocket,
  parseCliMessage,
  parseInitialRequest,
  renderCompletedElsewhere,
  runConnectionAttemptProtocol,
  sendPairedAssertionResult,
  sendPairedRegistrationResult,
  sessionFailureMessage,
  storageUnavailableMessage,
  terminateConnectionPhaseForCompletedElsewhere,
  terminatePhaseForCompletedElsewhere,
  terminatePhaseForPagehide,
  turnAuthorizedControl,
  turnUnavailableControl,
  waitForAttemptSignal,
} from './nearby.js';

const ED25519_PKCS8_SEED_PREFIX = Buffer.from(
  '302e020100300506032b657004220420',
  'hex',
);

async function deriveEd25519PublicKeyForTest(seed) {
  const privateKey = createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_SEED_PREFIX, Buffer.from(seed)]),
    format: 'der',
    type: 'pkcs8',
  });
  const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return new Uint8Array(spki.subarray(spki.length - 32));
}

function authorizeTurnWithPasskey(rendezvousId, challenge, cancellation) {
  return authorizeTurnWithPasskeyRuntime(
    rendezvousId,
    challenge,
    cancellation,
    deriveEd25519PublicKeyForTest,
  );
}

const TURN_CAPABILITY = 'A'.repeat(86);
const B16 = Buffer.alloc(16).toString('base64url');
const B32 = Buffer.alloc(32).toString('base64url');

function fakeSession() {
  const sent = [];
  let closed = false;
  return {
    sent,
    send(message) { sent.push(message); },
    close() { closed = true; },
    get closed() { return closed; },
  };
}

test('initial request variants reject unknown fields at every boundary', () => {
  const pinned = {
    type: 'request',
    request: {
      kind: 'assert',
      challenge: B16,
      prfSalt: B32,
      identitySalt: B32,
      identity: { kind: 'pinned', credentialId: 'AQ' },
      keyName: 'default',
      storage: 'choose',
    },
  };
  assert.equal(parseInitialRequest(pinned).kind, 'pinned');
  for (const invalid of [
    { ...pinned, extra: true },
    { ...pinned, request: { ...pinned.request, extra: true } },
    {
      ...pinned,
      request: {
        ...pinned.request,
        identity: { ...pinned.request.identity, extra: true },
      },
    },
  ]) {
    assert.throws(() => parseInitialRequest(invalid), /invalid/i);
  }

  const pairing = {
    type: 'pairing-request',
    cliCommitment: B32,
    request: {
      ...pinned.request,
      identity: { kind: 'pairing-any' },
      storage: 'remember',
    },
  };
  assert.equal(parseInitialRequest(pairing).kind, 'pairing');
  assert.throws(
    () => parseInitialRequest({ ...pairing, request: { ...pairing.request, extra: true } }),
    /invalid assertion request/i,
  );

  const registration = {
    type: 'pairing-request',
    cliCommitment: B32,
    request: {
      kind: 'register',
      challenge: B16,
      prfSalt: B32,
      userId: 'AQ',
      userName: 'keytap',
    },
  };
  assert.equal(parseInitialRequest(registration).kind, 'pairing');
  assert.throws(
    () => parseInitialRequest({
      ...registration,
      request: { ...registration.request, extra: true },
    }),
    /invalid registration request/i,
  );
});

test('CLI data-channel variants reject unknown fields', () => {
  assert.deepEqual(
    parseCliMessage({ type: 'sas-cli-reveal', nonce: B32 }, 'sas-cli-reveal'),
    { type: 'sas-cli-reveal', nonce: B32 },
  );
  assert.deepEqual(
    parseCliMessage({ type: 'initial-accepted' }, 'initial-accepted'),
    { type: 'initial-accepted' },
  );
  assert.deepEqual(
    parseCliMessage(
      { type: 'assertion-accepted', storage: 'stored' },
      'assertion-accepted',
    ),
    { type: 'assertion-accepted', storage: 'stored' },
  );

  for (const [message, expectedType] of [
    [{ type: 'sas-cli-reveal', nonce: B32, extra: true }, 'sas-cli-reveal'],
    [{ type: 'initial-accepted', extra: true }, 'initial-accepted'],
    [{ type: 'assertion-accepted', storage: 'stored', extra: true }, 'assertion-accepted'],
  ]) {
    assert.throws(() => parseCliMessage(message, expectedType), /invalid/i);
  }
  assert.throws(
    () => parseCliMessage(
      { type: 'protocol-error', code: 'invalid-message', extra: true },
      'initial-accepted',
    ),
    /invalid CLI protocol error/i,
  );
  assert.throws(
    () => parseCliMessage(
      { type: 'initial-rejected', reason: 'identity-mismatch', extra: true },
      'initial-accepted',
    ),
    /invalid CLI identity rejection/i,
  );
  assert.throws(
    () => parseCliMessage(
      { type: 'initial-indeterminate', reason: 'identity-durability-unknown', extra: true },
      'initial-accepted',
    ),
    /invalid CLI identity status/i,
  );
  assert.throws(
    () => parseCliMessage({ type: 'sas-cli-rejected', extra: true }, 'initial-accepted'),
    /invalid CLI pairing rejection/i,
  );
});

class MockEventTarget {
  constructor() {
    this.listeners = new Map();
  }

  addEventListener(type, listener) {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  removeEventListener(type, listener) {
    const listeners = this.listeners.get(type) ?? [];
    this.listeners.set(type, listeners.filter(candidate => candidate !== listener));
  }

  dispatch(type, event = {}) {
    for (const listener of [...(this.listeners.get(type) ?? [])]) {
      listener({ type, target: this, ...event });
    }
  }
}

function fakeDataTransport() {
  const peer = new MockEventTarget();
  peer.connectionState = 'connected';
  peer.closed = false;
  peer.close = () => {
    peer.closed = true;
    peer.connectionState = 'closed';
    peer.dispatch('connectionstatechange');
  };

  const channel = new MockEventTarget();
  channel.readyState = 'open';
  channel.sent = [];
  channel.send = message => channel.sent.push(message);
  channel.close = () => {
    if (channel.readyState === 'closed') return;
    channel.readyState = 'closed';
    channel.dispatch('close');
  };
  channel.message = message => channel.dispatch('message', { data: message });
  return { peer, channel };
}

async function withMockFetch(mock, operation) {
  const previousFetch = globalThis.fetch;
  globalThis.fetch = mock;
  try {
    return await operation();
  } finally {
    if (previousFetch === undefined) delete globalThis.fetch;
    else globalThis.fetch = previousFetch;
  }
}

async function withMockNavigatorCredentials(credentials, operation) {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  Object.defineProperty(globalThis, 'navigator', {
    configurable: true,
    value: { credentials },
  });
  try {
    return await operation();
  } finally {
    if (descriptor) Object.defineProperty(globalThis, 'navigator', descriptor);
    else delete globalThis.navigator;
  }
}

class MockWebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;
  static instances = [];

  constructor(url) {
    this.url = url;
    this.readyState = MockWebSocket.CONNECTING;
    this.listeners = new Map();
    this.sent = [];
    MockWebSocket.instances.push(this);
    queueMicrotask(() => {
      if (this.readyState !== MockWebSocket.CONNECTING) return;
      this.readyState = MockWebSocket.OPEN;
      this.dispatch('open');
    });
  }

  addEventListener(type, listener, options = {}) {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push({ listener, once: options.once === true });
    this.listeners.set(type, listeners);
  }

  removeEventListener(type, listener) {
    const listeners = this.listeners.get(type);
    if (!listeners) return;
    this.listeners.set(type, listeners.filter(entry => entry.listener !== listener));
  }

  dispatch(type, event = {}) {
    for (const entry of [...(this.listeners.get(type) ?? [])]) {
      if (entry.once) this.removeEventListener(type, entry.listener);
      entry.listener({ type, target: this, ...event });
    }
  }

  send(message) { this.sent.push(message); }

  close() {
    if (this.readyState === MockWebSocket.CLOSED) return;
    this.readyState = MockWebSocket.CLOSED;
    this.dispatch('close');
  }

  failRemotely() {
    this.dispatch('error');
  }

  closeRemotely() {
    this.close();
  }

  messageRemotely(data) {
    this.dispatch('message', { data });
  }
}

async function withMockWebSocket(operation) {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'WebSocket');
  MockWebSocket.instances.length = 0;
  Object.defineProperty(globalThis, 'WebSocket', {
    configurable: true,
    value: MockWebSocket,
  });
  try {
    return await operation();
  } finally {
    if (descriptor) Object.defineProperty(globalThis, 'WebSocket', descriptor);
    else delete globalThis.WebSocket;
  }
}

function turnChallenge() {
  return {
    kind: 'turn-passkey-challenge',
    challenge: new Uint8Array(32).fill(1),
    expiresAt: Date.now() + 60_000,
  };
}

test('an unexpected signaling close aborts an in-flight passkey prompt', async () => {
  await withMockWebSocket(async () => {
    const connection = { controller: new AbortController() };
    await openSignalSocket('A'.repeat(43), connection);
    assert.equal(
      MockWebSocket.instances[0].url,
      `wss://keytap-signal.julsh.workers.dev/signal/${'A'.repeat(43)}?role=approver`,
    );
    let promptSignal;
    const pending = withMockNavigatorCredentials({
      get(options) {
        promptSignal = options.signal;
        return new Promise((resolve, reject) => {
          options.signal.addEventListener(
            'abort',
            () => reject(options.signal.reason),
            { once: true },
          );
        });
      },
    }, () => authorizeTurnWithPasskey(
      'A'.repeat(43),
      turnChallenge(),
      connection.controller.signal,
    ));

    MockWebSocket.instances[0].closeRemotely();

    await assert.rejects(
      pending,
      error => error === connection.controller.signal.reason,
    );
    assert.equal(connection.controller.signal.aborted, true);
    assert.equal(promptSignal.aborted, true);
    assert.match(connection.controller.signal.reason.message, /signaling connection closed/i);
  });
});

test('an exact signaling completion stops connection setup without reporting failure', async () => {
  await withMockWebSocket(async () => {
    const connection = { controller: new AbortController() };
    const signaling = await openSignalSocket('A'.repeat(43), connection);
    const pending = signaling.next();

    MockWebSocket.instances[0].messageRemotely(JSON.stringify({
      type: 'completed-elsewhere',
    }));

    await assert.rejects(pending, CompletedElsewhereError);
    assert.equal(connection.controller.signal.aborted, true);
    assert.ok(connection.controller.signal.reason instanceof CompletedElsewhereError);
  });
});

test('signaling completion rejects non-exact lookalikes', async () => {
  await withMockWebSocket(async () => {
    const connection = { controller: new AbortController() };
    const signaling = await openSignalSocket('A'.repeat(43), connection);
    const pending = signaling.next();

    MockWebSocket.instances[0].messageRemotely(JSON.stringify({
      type: 'completed-elsewhere',
      extra: true,
    }));

    await assert.rejects(pending, /invalid signaling message/i);
    assert.equal(connection.controller.signal.aborted, true);
    assert.equal(connection.controller.signal.reason instanceof CompletedElsewhereError, false);
  });
});

test('an exact private-channel completion bypasses the response queue', async () => {
  const { peer, channel } = fakeDataTransport();
  let completedSession;
  const session = makeDataSession(peer, channel, sourceSession => {
    completedSession = sourceSession;
    sourceSession.close();
  });

  channel.message(JSON.stringify({ type: 'completed-elsewhere' }));
  await Promise.resolve();
  await Promise.resolve();

  assert.equal(completedSession, session);
  assert.equal(channel.readyState, 'closed');
  assert.equal(peer.closed, true);
  await assert.rejects(session.next(), /private (channel|connection) closed/i);
});

test('private-channel completion rejects non-exact lookalikes', async () => {
  const { peer, channel } = fakeDataTransport();
  let completed = false;
  const session = makeDataSession(peer, channel, () => { completed = true; });

  channel.message(JSON.stringify({ type: 'completed-elsewhere', extra: true }));
  await Promise.resolve();
  await Promise.resolve();

  assert.equal(completed, false);
  await assert.rejects(session.next(), /invalid completed-elsewhere message/i);
});

test('an unexpected signaling error aborts an in-flight TURN request', async () => {
  await withMockWebSocket(async () => {
    const connection = { controller: new AbortController() };
    await openSignalSocket('A'.repeat(43), connection);
    let requestSignal;
    const pending = withMockFetch((_url, options) => {
      requestSignal = options.signal;
      return new Promise((resolve, reject) => {
        options.signal.addEventListener(
          'abort',
          () => reject(options.signal.reason),
          { once: true },
        );
      });
    }, () => fetchTurnPasskeyChallenge(
      'A'.repeat(43),
      connection.controller.signal,
    ));

    MockWebSocket.instances[0].failRemotely();

    await assert.rejects(
      pending,
      error => error === connection.controller.signal.reason,
    );
    assert.equal(connection.controller.signal.aborted, true);
    assert.equal(requestSignal.aborted, true);
    assert.match(connection.controller.signal.reason.message, /signaling connection failed/i);
  });
});

test('intentionally closing signaling does not abort the established connection controller', async () => {
  await withMockWebSocket(async () => {
    const connection = { controller: new AbortController() };
    const signaling = await openSignalSocket('A'.repeat(43), connection);

    signaling.close();

    assert.equal(connection.controller.signal.aborted, false);
    assert.equal(MockWebSocket.instances[0].readyState, MockWebSocket.CLOSED);
  });
});

test('an invalid signaling frame aborts the shared connection controller', async () => {
  await withMockWebSocket(async () => {
    const connection = { controller: new AbortController() };
    await openSignalSocket('A'.repeat(43), connection);

    MockWebSocket.instances[0].messageRemotely('{');

    assert.equal(connection.controller.signal.aborted, true);
    assert.match(connection.controller.signal.reason.message, /invalid signaling message/i);
  });
});

test('an authorized TURN response returns only the filtered ICE servers', async () => {
  let requested;
  const iceServers = await withMockFetch(async (url, options) => {
    requested = { url, options };
    return new Response(JSON.stringify({
      iceServers: [{
        urls: ['turn:attacker.invalid:3478'],
        username: 'ephemeral-user',
        credential: 'ephemeral-password',
      }],
    }), { status: 200 });
  }, () => fetchTurnIceServers(
    'room-id',
    TURN_CAPABILITY,
    new AbortController().signal,
  ));

  assert.equal(requested.url, 'https://keytap-signal.julsh.workers.dev/signal/room-id/turn');
  assert.equal(requested.url.includes(TURN_CAPABILITY), false);
  assert.deepEqual(requested.options.headers, {
    Accept: 'application/json',
    Authorization: `Bearer ${TURN_CAPABILITY}`,
  });
  assert.equal(requested.options.credentials, 'omit');
  assert.equal(requested.options.redirect, 'error');
  assert.equal(iceServers[1].username, 'ephemeral-user');
  assert.equal(iceServers[1].credential, 'ephemeral-password');
});

test('only the exact bounded 403 payload means TURN is not allowlisted', async () => {
  const responses = [
    new Response(JSON.stringify({ kind: 'turn-not-allowlisted' }), { status: 403 }),
    new Response(JSON.stringify({ kind: 'turn-not-allowlisted', detail: 'extra' }), { status: 403 }),
    new Response(JSON.stringify({ kind: 'turn-not-allowlisted' }), { status: 500 }),
    new Response('{', { status: 403 }),
    new Response(JSON.stringify({ kind: 'turn-not-allowlisted' }), {
      status: 403,
      headers: { 'Content-Length': '1025' },
    }),
  ];

  await withMockFetch(async () => responses.shift(), async () => {
    await assert.rejects(
      fetchTurnIceServers('room', TURN_CAPABILITY, new AbortController().signal),
      TurnPasskeyNotAllowlistedError,
    );

    for (let index = 0; index < 4; index += 1) {
      await assert.rejects(
        fetchTurnIceServers('room', TURN_CAPABILITY, new AbortController().signal),
        TurnProviderUnavailableError,
      );
    }
  });
});

test('TURN network and malformed-success failures are provider errors', async () => {
  await withMockFetch(async () => { throw new TypeError('offline'); }, async () => {
    await assert.rejects(
      fetchTurnIceServers('room', TURN_CAPABILITY, new AbortController().signal),
      TurnProviderUnavailableError,
    );
  });
  await withMockFetch(async () => new Response('{', { status: 200 }), async () => {
    await assert.rejects(
      fetchTurnIceServers('room', TURN_CAPABILITY, new AbortController().signal),
      TurnProviderUnavailableError,
    );
  });
});

test('TURN credential retrieval preserves caller cancellation', async () => {
  const controller = new AbortController();
  const reason = new Error('page left');
  const pending = withMockFetch((_url, options) => new Promise((resolve, reject) => {
    options.signal.addEventListener('abort', () => reject(options.signal.reason), { once: true });
  }), () => fetchTurnIceServers('room', TURN_CAPABILITY, controller.signal));
  controller.abort(reason);
  await assert.rejects(pending, error => error === reason);

  const alreadyAborted = new AbortController();
  alreadyAborted.abort(reason);
  await assert.rejects(
    fetchTurnIceServers('room', TURN_CAPABILITY, alreadyAborted.signal),
    error => error === reason,
  );
});

test('TURN passkey challenge uses a mutation-safe request and parses only the strict shape', async () => {
  const rendezvousId = 'A'.repeat(43);
  const futureExpiry = Date.now() + 5 * 60_000;
  let requested;
  const challenge = await withMockFetch(async (url, options) => {
    requested = { url, options };
    return new Response(JSON.stringify({
      kind: 'turn-passkey-challenge',
      challenge: 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8',
      expiresAt: futureExpiry,
    }));
  }, () => fetchTurnPasskeyChallenge(rendezvousId, new AbortController().signal));

  assert.equal(
    requested.url,
    `https://keytap-signal.julsh.workers.dev/signal/${rendezvousId}/turn/challenge`,
  );
  assert.equal(requested.options.method, 'POST');
  assert.equal(requested.options.body, undefined);
  assert.equal(requested.options.credentials, 'omit');
  assert.equal(requested.options.cache, 'no-store');
  assert.equal(requested.options.redirect, 'error');
  assert.deepEqual(Object.keys(challenge).sort(), ['challenge', 'expiresAt', 'kind']);
  assert.equal(challenge.challenge.length, 32);

  await withMockFetch(async () => new Response(JSON.stringify({
    kind: 'turn-passkey-challenge',
    challenge: 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8',
    expiresAt: challenge.expiresAt,
    extra: true,
  })), async () => {
    await assert.rejects(
      fetchTurnPasskeyChallenge(rendezvousId, new AbortController().signal),
      TurnProviderUnavailableError,
    );
  });

  for (const expiresAt of [0, Date.now() - 1]) {
    await withMockFetch(async () => new Response(JSON.stringify({
      kind: 'turn-passkey-challenge',
      challenge: 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8',
      expiresAt,
    })), async () => {
      await assert.rejects(
        fetchTurnPasskeyChallenge(rendezvousId, new AbortController().signal),
        TurnProviderUnavailableError,
      );
    });
  }
});

test('identity-only WebAuthn authorizes TURN with the fixed proof wire and no PRF output', async () => {
  const rendezvousId = 'A'.repeat(43);
  const challenge = {
    kind: 'turn-passkey-challenge',
    challenge: Uint8Array.from({ length: 32 }, (_, index) => 0x20 + index),
    expiresAt: 2_000_000_000_000,
  };
  let ceremonyOptions;
  let authorizationRequest;
  const credentialId = new TextEncoder().encode('credential-owner');
  const identitySeed = Uint8Array.from({ length: 32 }, (_, index) => index);
  const capability = await withMockNavigatorCredentials({
    async get(options) {
      ceremonyOptions = options;
      return {
        rawId: credentialId,
        getClientExtensionResults() {
          return { prf: { results: { first: identitySeed.buffer.slice(0) } } };
        },
      };
    },
  }, () => withMockFetch(async (url, options) => {
    authorizationRequest = { url, options, body: JSON.parse(options.body) };
    return new Response(JSON.stringify({ kind: 'turn-authorized' }));
  }, () => authorizeTurnWithPasskey(
    rendezvousId,
    challenge,
    new AbortController().signal,
  )));

  assert.equal(ceremonyOptions.publicKey.rpId, 'keytap.jul.sh');
  assert.equal(ceremonyOptions.publicKey.userVerification, 'required');
  assert.equal(ceremonyOptions.publicKey.allowCredentials, undefined);
  assert.equal(ceremonyOptions.publicKey.extensions.prf.eval.first.length, 32);
  assert.equal(
    authorizationRequest.url,
    `https://keytap-signal.julsh.workers.dev/signal/${rendezvousId}/turn/authorize`,
  );
  assert.equal(authorizationRequest.options.method, 'POST');
  assert.equal(authorizationRequest.options.redirect, 'error');
  assert.deepEqual(Object.keys(authorizationRequest.body).sort(), [
    'challenge', 'credentialId', 'expiresAt', 'kind', 'publicKey', 'signature',
  ]);
  assert.equal(authorizationRequest.body.kind, 'turn-passkey-proof');
  assert.equal(authorizationRequest.body.credentialId, 'Y3JlZGVudGlhbC1vd25lcg');
  assert.equal(authorizationRequest.body.publicKey, 'A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg');
  assert.equal(
    authorizationRequest.body.signature,
    'Kq7yBsYegNIr5povtDGDpkwPryLT8KFBFKaBZ3Py_y1YaUBO7TGRq7yIrOUB6QWB0BYnU_XsGfCS59a8xRTLBg',
  );
  assert.equal(capability, authorizationRequest.body.signature);
  assert.match(capability, /^[A-Za-z0-9_-]{86}$/);
  assert.equal('prfFirst' in authorizationRequest.body, false);
  assert.equal('identitySeed' in authorizationRequest.body, false);
});

test('only exact authorization denial is classified as not allowlisted', async () => {
  const challenge = {
    kind: 'turn-passkey-challenge',
    challenge: new Uint8Array(32).fill(1),
    expiresAt: Date.now() + 60_000,
  };
  const credentials = {
    async get() {
      return {
        rawId: new Uint8Array([1]),
        getClientExtensionResults: () => ({
          prf: { results: { first: new Uint8Array(32).fill(2).buffer } },
        }),
      };
    },
  };
  await withMockNavigatorCredentials(credentials, () => withMockFetch(
    async () => new Response(JSON.stringify({ kind: 'turn-not-allowlisted' }), { status: 403 }),
    () => assert.rejects(
      authorizeTurnWithPasskey('A'.repeat(43), challenge, new AbortController().signal),
      TurnPasskeyNotAllowlistedError,
    ),
  ));
  await withMockNavigatorCredentials(credentials, () => withMockFetch(
    async () => new Response(
      JSON.stringify({ kind: 'turn-not-allowlisted', detail: 'extra' }),
      { status: 403 },
    ),
    () => assert.rejects(
      authorizeTurnWithPasskey('A'.repeat(43), challenge, new AbortController().signal),
      TurnProviderUnavailableError,
    ),
  ));
});

test('a challenge expiring during WebAuthn is not reported as an allowlist denial', async () => {
  const challenge = {
    kind: 'turn-passkey-challenge',
    challenge: new Uint8Array(32).fill(1),
    expiresAt: Date.now() + 60_000,
  };
  const credentials = {
    async get() {
      return {
        rawId: new Uint8Array([1]),
        getClientExtensionResults: () => ({
          prf: { results: { first: new Uint8Array(32).fill(2).buffer } },
        }),
      };
    },
  };
  await withMockNavigatorCredentials(credentials, () => withMockFetch(
    async () => new Response(
      JSON.stringify({ kind: 'turn-challenge-expired' }),
      { status: 409 },
    ),
    () => assert.rejects(
      authorizeTurnWithPasskey('A'.repeat(43), challenge, new AbortController().signal),
      error => error instanceof TurnProviderUnavailableError
        && !(error instanceof TurnPasskeyNotAllowlistedError),
    ),
  ));
});

test('cancelled relay approval stays distinct and never submits a proof', async () => {
  let fetchCalled = false;
  await withMockNavigatorCredentials({
    async get() { throw new DOMException('cancelled', 'NotAllowedError'); },
  }, () => withMockFetch(async () => {
    fetchCalled = true;
    throw new Error('must not submit');
  }, () => assert.rejects(
    authorizeTurnWithPasskey('A'.repeat(43), {
      kind: 'turn-passkey-challenge',
      challenge: new Uint8Array(32),
      expiresAt: Date.now() + 60_000,
    }, new AbortController().signal),
    TurnPasskeyCancelledError,
  )));
  assert.equal(fetchCalled, false);
});

test('local WebAuthn failure stays distinct from provider and allowlist failures', async () => {
  let fetchCalled = false;
  await withMockNavigatorCredentials({
    async get() { throw new DOMException('unsupported authenticator', 'SecurityError'); },
  }, () => withMockFetch(async () => {
    fetchCalled = true;
    throw new Error('must not submit');
  }, () => assert.rejects(
    authorizeTurnWithPasskey(
      'A'.repeat(43),
      turnChallenge(),
      new AbortController().signal,
    ),
    error => error instanceof TurnPasskeyUnavailableError
      && !(error instanceof TurnProviderUnavailableError)
      && !(error instanceof TurnPasskeyNotAllowlistedError),
  )));
  assert.equal(fetchCalled, false);
});

test('missing or invalid PRF output is a local passkey capability failure', async t => {
  for (const [name, extensionResults] of [
    ['missing PRF output', {}],
    ['invalid PRF output', {
      prf: { results: { first: new Uint8Array(31).buffer } },
    }],
  ]) {
    await t.test(name, async () => {
      let fetchCalled = false;
      await withMockNavigatorCredentials({
        async get() {
          return {
            rawId: new Uint8Array([1]),
            getClientExtensionResults: () => extensionResults,
          };
        },
      }, () => withMockFetch(async () => {
        fetchCalled = true;
        throw new Error('must not submit');
      }, () => assert.rejects(
        authorizeTurnWithPasskey(
          'A'.repeat(43),
          turnChallenge(),
          new AbortController().signal,
        ),
        error => error instanceof TurnPasskeyUnavailableError
          && !(error instanceof TurnProviderUnavailableError),
      )));
      assert.equal(fetchCalled, false);
    });
  }
});

test('TURN capability wire is exact and rejects malformed local capabilities', async () => {
  assert.deepEqual(
    turnAuthorizedControl(TURN_CAPABILITY),
    { type: 'turn-authorized', capability: TURN_CAPABILITY },
  );
  assert.deepEqual(
    Object.keys(turnAuthorizedControl(TURN_CAPABILITY)).sort(),
    ['capability', 'type'],
  );

  for (const malformed of ['', 'A'.repeat(85), `${TURN_CAPABILITY}=`]) {
    assert.throws(() => turnAuthorizedControl(malformed), TurnPasskeyUnavailableError);
  }

  let fetchCalled = false;
  await withMockFetch(async () => {
    fetchCalled = true;
    throw new Error('must not request credentials');
  }, () => assert.rejects(
    fetchTurnIceServers('room', 'not-a-capability', new AbortController().signal),
    TurnPasskeyUnavailableError,
  ));
  assert.equal(fetchCalled, false);
});

test('retry signaling accepts only the exact control and ignores its queued stale copy', async () => {
  const offer = { v: 1, from: 'cli', seq: 1, kind: 'offer', body: 'AA', signature: 'AA' };
  const accepting = { next: async () => ({ type: 'turn-required' }) };
  assert.deepEqual(
    await waitForAttemptSignal(accepting, 'accept'),
    { kind: 'turn-required' },
  );

  const queued = [{ type: 'turn-required' }, offer];
  const ignoring = { next: async () => queued.shift() };
  assert.deepEqual(
    await waitForAttemptSignal(ignoring, 'ignore-stale'),
    { kind: 'offer', envelope: offer },
  );

  const nonCanonical = { type: 'turn-required', extra: true };
  const strict = { next: async () => nonCanonical };
  assert.deepEqual(
    await waitForAttemptSignal(strict, 'accept'),
    { kind: 'offer', envelope: nonCanonical },
  );
});

test('CLI-first TURN-required runs authorization before the sequence-1 retry', async () => {
  const events = [];
  const sent = [];
  const challenge = turnChallenge();
  const relayIceServers = [{
    urls: ['turn:turn.cloudflare.com:3478?transport=udp'],
    username: 'relay-user',
    credential: 'relay-credential',
  }];
  const session = fakeSession();
  const sessionBinding = new Uint8Array([1, 2, 3]);
  const established = await runConnectionAttemptProtocol({
    cancellation: new AbortController().signal,
    sendTurnControl(message) {
      events.push('control:turn-authorized');
      sent.push(message);
    },
    async attemptConnection(spec) {
      events.push(`attempt:${spec.sequence}`);
      switch (spec.sequence) {
        case 0:
          assert.equal(spec.turnRequiredPolicy, 'accept');
          assert.deepEqual(spec.iceServers, [{
            urls: ['stun:stun.cloudflare.com:3478'],
          }]);
          return waitForAttemptSignal({
            async next() {
              events.push('cli:turn-required');
              return { type: 'turn-required' };
            },
          }, spec.turnRequiredPolicy);
        case 1:
          assert.equal(spec.turnRequiredPolicy, 'ignore-stale');
          assert.equal(spec.iceServers, relayIceServers);
          return { kind: 'connected', session, sessionBinding };
      }
      throw new Error('unexpected attempt sequence');
    },
    async requestRelayChallenge() {
      events.push('challenge');
      return challenge;
    },
    async waitForConsent() {
      events.push('consent');
    },
    async prepareRelay(receivedChallenge) {
      assert.equal(receivedChallenge, challenge);
      events.push('authorize');
      return { capability: TURN_CAPABILITY, iceServers: relayIceServers };
    },
    onRelayAuthorized() {
      events.push('relay-ready');
    },
  });

  assert.equal(established.session, session);
  assert.equal(established.sessionBinding, sessionBinding);
  assert.deepEqual(sent, [{ type: 'turn-authorized', capability: TURN_CAPABILITY }]);
  assert.deepEqual(events, [
    'attempt:0',
    'cli:turn-required',
    'consent',
    'challenge',
    'authorize',
    'control:turn-authorized',
    'relay-ready',
    'attempt:1',
  ]);
});

test('approver-first direct connectivity failure authorizes before the sequence-1 retry', async () => {
  const events = [];
  const sent = [];
  const challenge = turnChallenge();
  const relayIceServers = [{
    urls: ['turns:turn.cloudflare.com:443?transport=tcp'],
    username: 'relay-user',
    credential: 'relay-credential',
  }];
  const session = fakeSession();
  const sessionBinding = new Uint8Array([4, 5, 6]);
  const established = await runConnectionAttemptProtocol({
    cancellation: new AbortController().signal,
    sendTurnControl(message) {
      events.push('control:turn-authorized');
      sent.push(message);
    },
    async attemptConnection(spec) {
      events.push(`attempt:${spec.sequence}`);
      switch (spec.sequence) {
        case 0:
          assert.equal(spec.turnRequiredPolicy, 'accept');
          throw new PeerConnectionEstablishmentError('direct connectivity failed on approver');
        case 1:
          assert.equal(spec.turnRequiredPolicy, 'ignore-stale');
          assert.equal(spec.iceServers, relayIceServers);
          return { kind: 'connected', session, sessionBinding };
      }
      throw new Error('unexpected attempt sequence');
    },
    async requestRelayChallenge() {
      events.push('challenge');
      return challenge;
    },
    async waitForConsent() {
      events.push('consent');
    },
    async prepareRelay(receivedChallenge) {
      assert.equal(receivedChallenge, challenge);
      events.push('authorize');
      return { capability: TURN_CAPABILITY, iceServers: relayIceServers };
    },
    onRelayAuthorized() {
      events.push('relay-ready');
    },
  });

  assert.equal(established.session, session);
  assert.equal(established.sessionBinding, sessionBinding);
  assert.deepEqual(sent, [{ type: 'turn-authorized', capability: TURN_CAPABILITY }]);
  assert.deepEqual(events, [
    'attempt:0',
    'consent',
    'challenge',
    'authorize',
    'control:turn-authorized',
    'relay-ready',
    'attempt:1',
  ]);
});

test('unavailable passkey authorization emits one exact control and never retries', async () => {
  const failure = new TurnPasskeyUnavailableError('local identity proof unavailable');
  const attempts = [];
  const sent = [];
  let relayStarted = false;
  const pending = runConnectionAttemptProtocol({
    cancellation: new AbortController().signal,
    sendTurnControl: message => sent.push(message),
    async attemptConnection(spec) {
      attempts.push(spec.sequence);
      return { kind: 'turn-required' };
    },
    async requestRelayChallenge() { return turnChallenge(); },
    async waitForConsent() {},
    async prepareRelay() { throw failure; },
    onRelayAuthorized() { relayStarted = true; },
  });

  await assert.rejects(pending, error => error === failure);
  assert.deepEqual(attempts, [0]);
  assert.deepEqual(sent, [{
    type: 'turn-unavailable',
    reason: 'passkey-unavailable',
  }]);
  assert.equal(relayStarted, false);
});

test('mid-authorization signaling disconnect aborts without capability or retry', async () => {
  await withMockWebSocket(async () => {
    const connection = { controller: new AbortController() };
    const signaling = await openSignalSocket('A'.repeat(43), connection);
    const attempts = [];
    let relayStarted = false;
    let authorizationStarted;
    const started = new Promise(resolve => { authorizationStarted = resolve; });
    const pending = runConnectionAttemptProtocol({
      cancellation: connection.controller.signal,
      sendTurnControl: message => signaling.send(message),
      async attemptConnection(spec) {
        attempts.push(spec.sequence);
        return { kind: 'turn-required' };
      },
      async requestRelayChallenge() { return turnChallenge(); },
      async waitForConsent() {},
      prepareRelay() {
        authorizationStarted();
        return new Promise(() => {});
      },
      onRelayAuthorized() { relayStarted = true; },
    });
    await started;

    MockWebSocket.instances[0].closeRemotely();

    await assert.rejects(
      pending,
      error => error === connection.controller.signal.reason,
    );
    assert.deepEqual(attempts, [0]);
    assert.deepEqual(MockWebSocket.instances[0].sent, []);
    assert.equal(relayStarted, false);
  });
});

test('relay authorization failures remain distinct at the final error boundary', () => {
  const allowlistMessage = beforeSessionFailureMessage(new TurnPasskeyNotAllowlistedError());
  assert.match(allowlistMessage, /direct peer-to-peer connection failed/i);
  assert.match(allowlistMessage, /passkey identity is not on the TURN allowlist/i);
  assert.match(allowlistMessage, /Cloudflare quota/i);

  const cancelledMessage = beforeSessionFailureMessage(
    new TurnPasskeyCancelledError(new DOMException('cancelled', 'NotAllowedError')),
  );
  assert.match(cancelledMessage, /direct peer-to-peer connection failed/i);
  assert.match(cancelledMessage, /approval.*cancelled/i);
  assert.doesNotMatch(cancelledMessage, /not on the TURN allowlist/i);

  const providerMessage = beforeSessionFailureMessage(new TurnProviderUnavailableError());
  assert.match(providerMessage, /temporarily unavailable/i);
  assert.doesNotMatch(providerMessage, /not on the TURN allowlist|cancelled/i);

  const localProofMessage = beforeSessionFailureMessage(new TurnPasskeyUnavailableError());
  assert.match(localProofMessage, /direct peer-to-peer connection failed/i);
  assert.match(localProofMessage, /browser or passkey.*local identity proof/i);
  assert.match(localProofMessage, /supports PRF/i);
  assert.doesNotMatch(
    localProofMessage,
    /not on the TURN allowlist|Cloudflare quota|temporarily unavailable/i,
  );

  const genericMessage = beforeSessionFailureMessage(
    new PeerConnectionEstablishmentError('the private connection failed'),
  );
  assert.doesNotMatch(genericMessage, /allowlisted|Cloudflare quota/i);
});

test('approver retry controls are exact and preserve the authorization outcome', () => {
  assert.deepEqual(
    turnUnavailableControl(new TurnPasskeyNotAllowlistedError()),
    { type: 'turn-unavailable', reason: 'not-allowlisted' },
  );
  assert.deepEqual(
    turnUnavailableControl(new TurnPasskeyCancelledError(new Error('cancelled'))),
    { type: 'turn-unavailable', reason: 'cancelled' },
  );
  assert.deepEqual(
    turnUnavailableControl(new TurnProviderUnavailableError()),
    { type: 'turn-unavailable', reason: 'provider-unavailable' },
  );
  assert.deepEqual(
    turnUnavailableControl(new TurnPasskeyUnavailableError()),
    { type: 'turn-unavailable', reason: 'passkey-unavailable' },
  );
});

test('pagehide cancels every in-flight connection attempt state', () => {
  for (const kind of [
    'connecting-direct',
    'relay-authorizing',
    'connecting-relay',
  ]) {
    const controller = new AbortController();
    terminatePhaseForPagehide({ kind, data: { controller } });
    assert.equal(controller.signal.aborted, true, kind);
  }
});

test('Mac completion aborts active WebAuthn and closes the private session', () => {
  for (const kind of ['first-busy', 'pairing-ceremony']) {
    const controller = new AbortController();
    const session = fakeSession();
    const nextPhase = terminatePhaseForCompletedElsewhere({
      kind,
      data: { controller, session },
    }, session);

    assert.deepEqual(nextPhase, { kind: 'completed-elsewhere' }, kind);
    assert.equal(controller.signal.aborted, true, kind);
    assert.equal(controller.signal.reason.name, 'AbortError', kind);
    assert.match(controller.signal.reason.message, /completed on the Mac/i, kind);
    assert.equal(session.closed, true, kind);
    assert.deepEqual(session.sent, [], kind);
  }
});

test('Mac completion closes idle and acknowledgement phases without sending a result', () => {
  for (const currentPhase of [
    { kind: 'disposition-choice', data: { kind: 'pinned' } },
    { kind: 'assertion-ack', data: {} },
  ]) {
    const session = fakeSession();
    currentPhase.data.session = session;
    const nextPhase = terminatePhaseForCompletedElsewhere(currentPhase, session);

    assert.deepEqual(nextPhase, { kind: 'completed-elsewhere' }, currentPhase.kind);
    assert.equal(session.closed, true, currentPhase.kind);
    assert.deepEqual(session.sent, [], currentPhase.kind);
  }
});

test('a stale private session cannot cancel the current WebAuthn ceremony', () => {
  const controller = new AbortController();
  const currentSession = fakeSession();
  const staleSession = fakeSession();
  const currentPhase = {
    kind: 'first-busy',
    data: { controller, session: currentSession },
  };

  assert.equal(
    terminatePhaseForCompletedElsewhere(currentPhase, staleSession),
    currentPhase,
  );
  assert.equal(controller.signal.aborted, false);
  assert.equal(currentSession.closed, false);
  assert.equal(staleSession.closed, true);
});

test('Mac completion from signaling transitions only its active connection', () => {
  const connection = { controller: new AbortController() };
  const currentPhase = { kind: 'connecting-direct', data: connection };
  assert.deepEqual(
    terminateConnectionPhaseForCompletedElsewhere(currentPhase, connection),
    { kind: 'completed-elsewhere' },
  );
  assert.equal(connection.controller.signal.aborted, true);

  const staleConnection = { controller: new AbortController() };
  assert.equal(
    terminateConnectionPhaseForCompletedElsewhere(currentPhase, staleConnection),
    currentPhase,
  );
  assert.equal(staleConnection.controller.signal.aborted, false);
});

test('Mac completion renders a clear terminal state', () => {
  const elements = Object.fromEntries([
    'title', 'summary', 'explainer', 'details', 'offer', 'pairing', 'start', 'status', 'alert',
  ].map(id => [id, {
    hidden: false,
    removed: false,
    focused: false,
    textContent: 'stale',
    append(value) { this.textContent += String(value); },
    focus() { this.focused = true; },
    remove() { this.removed = true; },
  }]));
  const previousDocument = globalThis.document;
  globalThis.document = {
    title: '',
    getElementById(id) { return elements[id]; },
  };
  try {
    renderCompletedElsewhere();
    assert.equal(globalThis.document.title, 'keytap: approved on Mac');
    assert.equal(elements.title.textContent, 'Approved on the Mac');
    assert.equal(elements.summary.hidden, true);
    assert.equal(elements.offer.hidden, true);
    assert.equal(elements.pairing.hidden, true);
    assert.equal(elements.start.removed, true);
    assert.match(elements.status.textContent, /approval on the Mac completed first/i);
    assert.match(elements.status.textContent, /device.*not used/i);
    assert.equal(elements.status.focused, true);
  } finally {
    if (previousDocument === undefined) delete globalThis.document;
    else globalThis.document = previousDocument;
  }
});

test('pagehide cancels a connection waiting for relay consent', () => {
  const controller = new AbortController();
  terminatePhaseForPagehide({
    kind: 'relay-consent',
    data: {
      connection: { controller },
      proceed() {},
    },
  });
  assert.equal(controller.signal.aborted, true);
});

test('pagehide aborts WebAuthn before closing a normal request', () => {
  const controller = new AbortController();
  const session = fakeSession();
  terminatePhaseForPagehide({
    kind: 'first-busy',
    data: { controller, session },
  });
  assert.equal(controller.signal.aborted, true);
  assert.deepEqual(session.sent, [{ type: 'done' }]);
  assert.equal(session.closed, true);
});

test('pagehide aborts pairing WebAuthn and rejects without a result', () => {
  const controller = new AbortController();
  const session = fakeSession();
  terminatePhaseForPagehide({
    kind: 'pairing-ceremony',
    data: { controller, session },
  });
  assert.equal(controller.signal.aborted, true);
  assert.deepEqual(session.sent, [{ type: 'sas-approver-rejected' }]);
  assert.equal(session.closed, true);
});

test('pairing results are sent immediately without a release handshake', () => {
  const registrationSession = fakeSession();
  sendPairedRegistrationResult(registrationSession, {
    rawId: new Uint8Array([1, 2, 3]),
  });
  assert.deepEqual(registrationSession.sent, [{
    type: 'paired-registration-result',
    credentialId: 'AQID',
  }]);

  const assertionSession = fakeSession();
  const prfFirst = new Uint8Array([4, 5, 6]);
  sendPairedAssertionResult(assertionSession, {
    credentialId: new Uint8Array([1, 2, 3]),
    prfFirst,
    identity: { publicKey: 'key', signature: 'signature' },
  }, 'remember');
  assert.deepEqual(assertionSession.sent, [{
    type: 'paired-assertion-result',
    credentialId: 'AQID',
    prfFirst: 'BAUG',
    identity: { publicKey: 'key', signature: 'signature' },
    disposition: 'remember',
  }]);
  assert.deepEqual(prfFirst, new Uint8Array(3));
});

test('identity storage failure is not described as an identity mismatch', () => {
  const registration = initialRejectionMessage('identity-store-unavailable', true);
  const assertion = initialRejectionMessage('identity-store-unavailable', false);
  assert.match(registration, /could not save the trusted identity/i);
  assert.match(registration, /received the passkey result/i);
  assert.match(assertion, /could not access its trusted identity store/i);
  assert.doesNotMatch(assertion, /did not match/i);
});

test('post-result disconnect does not claim that nothing was sent', () => {
  const registration = sessionFailureMessage(new Error('closed'), 'registration-ack');
  const assertion = sessionFailureMessage(new Error('closed'), 'assertion-ack');
  assert.match(registration, /result was sent/i);
  assert.match(registration, /check the terminal/i);
  assert.doesNotMatch(registration, /nothing else was sent/i);
  assert.match(assertion, /result was sent/i);
  assert.match(assertion, /check the terminal/i);
  assert.doesNotMatch(assertion, /nothing else was sent/i);
});

test('durability-indeterminate copy does not claim success or ordinary rejection', () => {
  const registration = initialIndeterminateMessage(true);
  const assertion = initialIndeterminateMessage(false);
  assert.match(registration, /status unknown/i);
  assert.match(registration, /saved durably/i);
  assert.match(registration, /check the terminal/i);
  assert.match(registration, /init --force/i);
  assert.doesNotMatch(registration, /success|nothing was sent/i);
  assert.match(assertion, /status unknown/i);
  assert.match(assertion, /refused the returned key/i);
  assert.doesNotMatch(assertion, /success|accepted/i);
});

test('storage failure copy reports receipt without claiming use or success', () => {
  const message = storageUnavailableMessage();
  assert.match(message, /received the approved key/i);
  assert.match(message, /could not store/i);
  assert.match(message, /check the terminal/i);
  assert.doesNotMatch(message, /\bsent\b|\bused\b|remembered successfully/i);
});

test('pagehide closes a pre-assertion pinned choice without leaving the CLI waiting', () => {
  const session = fakeSession();
  terminatePhaseForPagehide({
    kind: 'disposition-choice',
    data: {
      kind: 'pinned',
      session,
    },
  });
  assert.deepEqual(session.sent, [{ type: 'done' }]);
  assert.equal(session.closed, true);
});

test('pagehide rejects a pre-assertion pairing choice', () => {
  const session = fakeSession();
  terminatePhaseForPagehide({
    kind: 'disposition-choice',
    data: {
      kind: 'pairing',
      session,
    },
  });
  assert.deepEqual(session.sent, [{ type: 'sas-approver-rejected' }]);
  assert.equal(session.closed, true);
});

test('a persisted page restore replaces stale controls with expired guidance', () => {
  const elements = Object.fromEntries([
    'title', 'summary', 'explainer', 'details', 'offer', 'pairing', 'start', 'status', 'alert',
  ].map(id => [id, {
    hidden: false,
    removed: false,
    focused: false,
    textContent: 'stale',
    append(value) { this.textContent += String(value); },
    focus() { this.focused = true; },
    remove() { this.removed = true; },
  }]));
  const previousDocument = globalThis.document;
  globalThis.document = {
    title: '',
    getElementById(id) { return elements[id]; },
  };
  try {
    handlePageShow({ persisted: false });
    assert.equal(elements.offer.hidden, false);
    assert.equal(elements.start.removed, false);
    handlePageShow({ persisted: true });
    assert.equal(globalThis.document.title, 'keytap: request expired');
    assert.equal(elements.title.textContent, 'Request expired');
    assert.equal(elements.offer.hidden, true);
    assert.equal(elements.pairing.hidden, true);
    assert.equal(elements.start.removed, true);
    assert.match(elements.alert.textContent, /expired/i);
    assert.match(elements.alert.textContent, /fresh approval link/i);
    assert.equal(elements.alert.focused, true);
  } finally {
    if (previousDocument === undefined) delete globalThis.document;
    else globalThis.document = previousDocument;
  }
});
