import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  CompletedElsewhereError,
  LocalPairingRejectionError,
  PasskeyPrfUnavailableError,
  RelaySession,
  assertionProofBinding,
  classifyCreatedCredential,
  exactCliPublicKeyFromFragment,
  failureOutcome,
  handlePageShow,
  isTopLevelContext,
  relayUrl,
  registrationIdentitySeed,
  revealTopLevelPage,
  suspendPhaseForPagehide,
  terminateForPagehide,
} from './nearby.js';
import {
  IdentityProofUnavailableError,
  InitialIndeterminateError,
  InitialRejectionError,
  PairingRejectedError,
  ProtocolError,
  relayRoomId,
} from './nearby-protocol.js';

class MockSocket {
  constructor() {
    this.readyState = 1;
    this.listeners = new Map();
    this.sent = [];
    this.closed = false;
  }

  addEventListener(type, listener) {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  dispatch(type, event = {}) {
    for (const listener of [...(this.listeners.get(type) ?? [])]) {
      listener({ type, target: this, ...event });
    }
  }

  send(value) { this.sent.push(value); }

  close() {
    this.closed = true;
    this.readyState = 3;
  }
}

function flush() {
  return new Promise(resolve => setTimeout(resolve, 0));
}

test('relay session preserves authenticated raw request bytes', async () => {
  const socket = new MockSocket();
  const controller = new AbortController();
  const raw = new TextEncoder().encode('{"type":"request"}');
  const cipher = {
    async open() { return { value: { type: 'request' }, bytes: raw }; },
    async seal() { return new Uint8Array([2]); },
  };
  const session = new RelaySession(socket, cipher, controller);
  socket.dispatch('message', { data: new Uint8Array([2]).buffer });
  const opened = await session.nextRaw();
  assert.deepEqual(opened.value, { type: 'request' });
  assert.deepEqual(opened.bytes, raw);
  assert.equal(controller.signal.aborted, false);
});

test('only exact authenticated completion interrupts an active ceremony', async () => {
  for (const [value, completed] of [
    [{ type: 'completed-elsewhere' }, true],
    [{ type: 'completed-elsewhere', extra: true }, false],
    [{ type: 'completed_elsewhere' }, false],
  ]) {
    const socket = new MockSocket();
    const controller = new AbortController();
    const cipher = {
      async open() { return { value, bytes: new Uint8Array([1]) }; },
      async seal() { return new Uint8Array([2]); },
    };
    const session = new RelaySession(socket, cipher, controller);
    socket.dispatch('message', { data: new Uint8Array([2]).buffer });
    await flush();
    assert.equal(controller.signal.aborted, completed);
    if (completed) assert.ok(controller.signal.reason instanceof CompletedElsewhereError);
    session.close();
  }
});

test('relay close aborts WebAuthn while an intentional close does not', async () => {
  const cipher = { open() {}, seal() {} };
  const unexpectedSocket = new MockSocket();
  const unexpectedController = new AbortController();
  new RelaySession(unexpectedSocket, cipher, unexpectedController);
  unexpectedSocket.dispatch('close');
  await flush();
  assert.equal(unexpectedController.signal.aborted, true);
  assert.match(unexpectedController.signal.reason.message, /relay closed/i);

  const expectedSocket = new MockSocket();
  const expectedController = new AbortController();
  const expected = new RelaySession(expectedSocket, cipher, expectedController);
  expected.close();
  expectedSocket.dispatch('close');
  assert.equal(expectedController.signal.aborted, false);
});

test('final acknowledgement remains consumable when close follows its frame', async () => {
  const socket = new MockSocket();
  const controller = new AbortController();
  let finishDecrypt;
  const decrypting = new Promise(resolve => { finishDecrypt = resolve; });
  const cipher = {
    open() { return decrypting; },
    async seal() { return new Uint8Array([2]); },
  };
  const session = new RelaySession(socket, cipher, controller);
  const acknowledgement = session.next();
  socket.dispatch('message', { data: new Uint8Array([2]).buffer });
  socket.dispatch('close');
  assert.equal(controller.signal.aborted, false);
  finishDecrypt({
    value: { type: 'assertion-accepted', storage: 'stored' },
    bytes: new TextEncoder().encode('{"type":"assertion-accepted","storage":"stored"}'),
  });
  assert.deepEqual(await acknowledgement, {
    type: 'assertion-accepted',
    storage: 'stored',
  });
  await flush();
  assert.equal(controller.signal.aborted, true);
  assert.match(controller.signal.reason.message, /relay closed/i);
});

test('pagehide aborts all work and closes the relay', () => {
  const controller = new AbortController();
  const session = { closed: false, close() { this.closed = true; } };
  terminateForPagehide(controller, session);
  assert.equal(controller.signal.aborted, true);
  assert.equal(controller.signal.reason.name, 'AbortError');
  assert.equal(session.closed, true);
});

test('failure outcomes never claim rollback after a result was sent', () => {
  const before = failureOutcome(new ProtocolError('closed'), { kind: 'ceremony' });
  assert.equal(before.kind, 'failed');
  assert.match(before.message, /nothing was sent/i);

  const registration = failureOutcome(new ProtocolError('closed'), {
    kind: 'sent',
    result: { kind: 'registration' },
  });
  assert.equal(registration.kind, 'registration-indeterminate');
  assert.match(registration.message, /result was sent/i);
  assert.match(registration.message, /check the terminal/i);
  assert.doesNotMatch(registration.message, /nothing was sent/i);

  const assertion = failureOutcome(new ProtocolError('closed'), {
    kind: 'sent',
    result: { kind: 'assertion', keyName: 'deploy', disposition: 'once' },
  });
  assert.equal(assertion.kind, 'assertion-indeterminate');
  assert.match(assertion.message, /result was sent/i);
  assert.doesNotMatch(assertion.message, /nothing was sent/i);
});

test('created registration state warns about a passkey the CLI did not save', () => {
  for (const credential of [
    { kind: 'identified', credentialId: new Uint8Array([1, 2, 3]) },
    { kind: 'malformed' },
  ]) {
    const outcome = failureOutcome(new Error('unsupported PRF'), {
      kind: 'registration-created',
      session: {},
      credential,
    });
    assert.equal(outcome.kind, 'registration-created-unsaved');
    assert.match(outcome.message, /passkey may have been created/i);
    assert.match(outcome.message, /CLI did not save/i);
    assert.match(outcome.message, /passkey settings/i);
    assert.match(outcome.message, /remove.*before retrying/i);
    assert.doesNotMatch(outcome.message, /nothing was sent/i);
  }
  for (const error of [new PasskeyPrfUnavailableError(), new IdentityProofUnavailableError()]) {
    const outcome = failureOutcome(error, {
      kind: 'registration-created',
      session: {},
      credential: { kind: 'identified', credentialId: new Uint8Array([1]) },
    });
    assert.equal(outcome.kind, 'registration-created-unsaved');
    assert.match(outcome.message, /passkey may have been created/i);
  }
});

test('registration credential IDs are classified as a strict bounded sum', () => {
  for (const rawId of [new Uint8Array([1]), new Uint8Array(1024).fill(2)]) {
    const classified = classifyCreatedCredential({ rawId });
    assert.equal(classified.kind, 'identified');
    assert.deepEqual(classified.credentialId, rawId);
  }
  for (const credential of [
    null,
    {},
    { rawId: new Uint8Array() },
    { rawId: new Uint8Array(1025) },
    { rawId: Symbol('invalid') },
  ]) {
    assert.deepEqual(classifyCreatedCredential(credential), { kind: 'malformed' });
  }
});

test('local PRF and identity-proof incompatibility do not blame the relay', () => {
  for (const error of [new PasskeyPrfUnavailableError(), new IdentityProofUnavailableError()]) {
    const outcome = failureOutcome(error, {
      kind: 'ceremony',
      session: {},
      operation: {
        kind: 'assertion',
        request: {},
        binding: {},
        disposition: 'once',
      },
    });
    assert.equal(outcome.kind, 'capability-unavailable');
    assert.match(outcome.message, /browser|passkey/i);
    assert.match(outcome.message, /no key result was sent/i);
    assert.doesNotMatch(outcome.message, /relay|fresh (?:approval )?link/i);
  }
});

test('terminal outcomes distinguish rejection, durability, and local completion', () => {
  const pairingErrors = [new PairingRejectedError(), new LocalPairingRejectionError()];
  for (const error of pairingErrors) {
    const outcome = failureOutcome(error, { kind: 'sas' });
    assert.equal(outcome.kind, 'pairing-rejected');
    assert.match(outcome.message, /no passkey prompt opened/i);
  }

  const mismatch = failureOutcome(
    new InitialRejectionError('identity-mismatch'),
    { kind: 'sent', result: { kind: 'assertion' } },
  );
  assert.equal(mismatch.kind, 'identity-rejected');
  assert.match(mismatch.message, /did not match/i);

  const store = failureOutcome(
    new InitialRejectionError('identity-store-unavailable'),
    { kind: 'sent', result: { kind: 'registration' } },
  );
  assert.equal(store.kind, 'identity-store-unavailable');
  assert.match(store.message, /durably save or access/i);
  assert.doesNotMatch(store.message, /did not match/i);

  const unknown = failureOutcome(
    new InitialIndeterminateError('identity-durability-unknown'),
    { kind: 'sent', result: { kind: 'registration' } },
  );
  assert.equal(unknown.kind, 'identity-indeterminate');
  assert.match(unknown.message, /could not confirm durable/i);

  const completed = failureOutcome(new CompletedElsewhereError(), { kind: 'ceremony' });
  assert.equal(completed.kind, 'completed-elsewhere');
  assert.match(completed.message, /Mac completed first/i);
});

test('persisted page restore replaces stale controls with an expired terminal state', () => {
  const elements = Object.fromEntries(
    ['title', 'summary', 'details', 'content', 'status', 'alert'].map(id => [id, {
      hidden: false,
      textContent: 'stale',
      focused: false,
      replaceChildren() { this.textContent = ''; },
      focus() { this.focused = true; },
    }]),
  );
  const previousDocument = globalThis.document;
  globalThis.document = {
    title: '',
    getElementById(id) { return elements[id]; },
  };
  try {
    handlePageShow({ persisted: false });
    assert.equal(elements.title.textContent, 'stale');
    handlePageShow({ persisted: true });
    assert.equal(elements.title.textContent, 'Request expired');
    assert.match(elements.alert.textContent, /fresh approval link/i);
    assert.equal(elements.details.hidden, true);
    assert.equal(elements.alert.focused, true);
  } finally {
    if (previousDocument === undefined) delete globalThis.document;
    else globalThis.document = previousDocument;
  }
});

for (const { name, phase, title, message } of [
  {
    name: 'a created registration',
    phase: { kind: 'registration-created', session: {}, credential: { kind: 'malformed' } },
    title: 'Passkey created; setup incomplete',
    message: /CLI did not save|check the terminal/i,
  },
  {
    name: 'a sent registration result',
    phase: { kind: 'sent', session: {}, result: { kind: 'registration' } },
    title: 'Setup status unknown',
    message: /result was sent.*check the terminal/i,
  },
  {
    name: 'a sent assertion result',
    phase: {
      kind: 'sent',
      session: {},
      result: { kind: 'assertion', keyName: 'deploy', disposition: 'once' },
    },
    title: 'Approval status unknown',
    message: /result was sent.*check the terminal/i,
  },
]) {
  test(`persisted page restore preserves ${name}`, () => {
    const elements = Object.fromEntries(
      ['title', 'summary', 'details', 'content', 'status', 'alert'].map(id => [id, {
        hidden: false,
        textContent: 'stale',
        focused: false,
        replaceChildren() { this.textContent = ''; },
        focus() { this.focused = true; },
      }]),
    );
    const previousDocument = globalThis.document;
    globalThis.document = {
      title: '',
      getElementById(id) { return elements[id]; },
    };
    try {
      const suspended = suspendPhaseForPagehide(phase);
      assert.equal(suspended.kind, 'suspended');
      handlePageShow({ persisted: true }, suspended);
      assert.equal(elements.title.textContent, title);
      assert.match(elements.alert.textContent, message);
      assert.doesNotMatch(elements.alert.textContent, /fresh approval link/i);
      assert.equal(elements.details.hidden, true);
      assert.equal(elements.alert.focused, true);
    } finally {
      if (previousDocument === undefined) delete globalThis.document;
      else globalThis.document = previousDocument;
    }
  });
}

test('approval page is revealed and started only in a top-level context', () => {
  const classes = [];
  const root = { classList: { add(value) { classes.push(value); } } };
  const topLevel = {};
  topLevel.top = topLevel;
  topLevel.self = topLevel;
  assert.equal(isTopLevelContext(topLevel), true);
  assert.equal(revealTopLevelPage(topLevel, root), true);
  assert.deepEqual(classes, ['approval-top-level']);

  const framed = { top: {}, self: {} };
  assert.equal(isTopLevelContext(framed), false);
  assert.equal(revealTopLevelPage(framed, root), false);
  assert.deepEqual(classes, ['approval-top-level']);

  const inaccessible = { self: {} };
  Object.defineProperty(inaccessible, 'top', { get() { throw new Error('cross-origin'); } });
  assert.equal(isTopLevelContext(inaccessible), false);
});

test('relay URL is exact and carries no private material', async () => {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
  const cliPublic = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const room = await relayRoomId(cliPublic);
  const url = new URL(await relayUrl(cliPublic));
  assert.equal(url.href, `wss://keytap-relay.julsh.workers.dev/room/${room}?role=approver`);
  assert.equal(url.href.includes(Buffer.from(cliPublic).toString('base64url')), false);
});

test('fragment parser accepts only the exact canonical key and erases it first', async () => {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
  const cliPublic = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  const encoded = Buffer.from(cliPublic).toString('base64url');
  const previousLocation = globalThis.location;
  const previousHistory = globalThis.history;
  const replacements = [];
  globalThis.location = { hash: `#key=${encoded}`, pathname: '/nearby', search: '' };
  globalThis.history = { replaceState(...args) { replacements.push(args); } };
  try {
    assert.deepEqual(exactCliPublicKeyFromFragment(), cliPublic);
    assert.deepEqual(replacements, [[null, '', '/nearby']]);
    for (const hash of [
      `#key=${encoded}&extra=1`,
      `#key=%${encoded.charCodeAt(0).toString(16)}${encoded.slice(1)}`,
      `#key=${encoded}&`,
      `#key=${encoded}=`,
      `#other=${encoded}`,
    ]) {
      globalThis.location.hash = hash;
      assert.throws(() => exactCliPublicKeyFromFragment(), /approval link|CLI key/i);
    }
    assert.equal(replacements.length, 6);
  } finally {
    if (previousLocation === undefined) delete globalThis.location;
    else globalThis.location = previousLocation;
    if (previousHistory === undefined) delete globalThis.history;
    else globalThis.history = previousHistory;
  }
});

test('registration confirms words before starting its passkey ceremony', async () => {
  const source = await readFile(new URL('./nearby.js', import.meta.url), 'utf8');
  const main = source.slice(source.indexOf('export async function main()'));
  const registration = main.slice(
    main.indexOf("case 'register':"),
    main.indexOf("case 'assert':"),
  );
  assert.ok(registration.indexOf('await runSas(') < registration.indexOf('completeRegistration('));

  const confirmation = source.slice(
    source.indexOf('async function confirmPairingWords'),
    source.indexOf('async function runSas'),
  );
  assert.match(confirmation, /sas-approver-confirmed/);
  assert.match(confirmation, /sas-cli-confirmed/);
  assert.doesNotMatch(confirmation, /navigator\.credentials/);
});

test('assertion proof binding runs words only for an identity not yet pinned', async () => {
  const digest = new Uint8Array(32).fill(1);
  const sessionBinding = new Uint8Array(32).fill(2);
  const requestFrameBytes = new Uint8Array([3, 4, 5]);

  for (const identity of [
    { kind: 'pairing-any' },
    { kind: 'pairing-credential', credentialId: new Uint8Array([6]) },
  ]) {
    let confirmations = 0;
    const binding = await assertionProofBinding(
      identity,
      sessionBinding,
      requestFrameBytes,
      async () => {
        confirmations += 1;
        return digest;
      },
    );
    assert.equal(confirmations, 1);
    assert.equal(binding.kind, 'first-pair-sas');
    assert.equal(binding.digest, digest);
  }

  const pinned = await assertionProofBinding(
    { kind: 'pinned', credentialId: new Uint8Array([7]) },
    sessionBinding,
    requestFrameBytes,
    async () => { throw new Error('words must not run for a pinned identity'); },
  );
  assert.equal(pinned.kind, 'pinned-identity');
  assert.equal(pinned.sessionBinding, sessionBinding);
  assert.equal(pinned.requestFrameBytes, requestFrameBytes);

  await assert.rejects(
    assertionProofBinding(
      { kind: 'invalid' },
      sessionBinding,
      requestFrameBytes,
      async () => digest,
    ),
    ProtocolError,
  );
});

function credentialWithPrf(rawId, first) {
  return {
    rawId,
    getClientExtensionResults() {
      return { prf: { results: first ? { first } : {} } };
    },
  };
}

test('registration uses create-time PRF output or targets the new credential once', async () => {
  const credentialId = new Uint8Array([1, 2, 3]);
  const createTimeSeed = new Uint8Array(32).fill(4);
  assert.deepEqual(
    await registrationIdentitySeed(
      credentialWithPrf(credentialId, createTimeSeed),
      {},
      credentialId,
      new AbortController().signal,
    ),
    createTimeSeed,
  );

  const fallbackSeed = new Uint8Array(32).fill(5);
  const request = {
    challenge: new Uint8Array(32).fill(6),
    identitySalt: new Uint8Array(32).fill(7),
  };
  const calls = [];
  const previousLocation = globalThis.location;
  const navigatorDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  globalThis.location = { hostname: 'keytap.jul.sh' };
  Object.defineProperty(globalThis, 'navigator', {
    configurable: true,
    value: {
      credentials: {
        async get(options) {
          calls.push(options);
          return credentialWithPrf(credentialId, fallbackSeed);
        },
      },
    },
  });
  try {
    const signal = new AbortController().signal;
    assert.deepEqual(
      await registrationIdentitySeed(
        credentialWithPrf(credentialId),
        request,
        credentialId,
        signal,
      ),
      fallbackSeed,
    );
    assert.equal(calls.length, 1);
    assert.equal(calls[0].signal, signal);
    assert.deepEqual(calls[0].publicKey.allowCredentials, [
      { type: 'public-key', id: credentialId },
    ]);
    assert.deepEqual(calls[0].publicKey.extensions.prf.eval.first, request.identitySalt);
    await assert.rejects(
      registrationIdentitySeed(
        credentialWithPrf(credentialId),
        request,
        new Uint8Array([9]),
        signal,
      ),
      PasskeyPrfUnavailableError,
    );
  } finally {
    if (previousLocation === undefined) delete globalThis.location;
    else globalThis.location = previousLocation;
    if (navigatorDescriptor) Object.defineProperty(globalThis, 'navigator', navigatorDescriptor);
    else delete globalThis.navigator;
  }
});

test('registration creation is modeled before PRF validation and relay send', async () => {
  const source = await readFile(new URL('./nearby.js', import.meta.url), 'utf8');
  const registration = source.slice(
    source.indexOf('async function completeRegistration'),
    source.indexOf('async function completeAssertion'),
  );
  const created = registration.indexOf("phase = { kind: 'registration-created'");
  assert.ok(registration.indexOf('await runRegistration(') < created);
  assert.ok(created < registration.indexOf('await registrationIdentitySeed('));
  assert.ok(created < registration.indexOf('await createRegistrationIdentityProof('));
  assert.ok(created < registration.indexOf('await session.send('));
  assert.match(source, /const RELAY_MESSAGE_TIMEOUT_MS = 150_000/);
  assert.match(source, /const WEBAUTHN_TIMEOUT_MS = 120_000/);
});

test('approval shell defaults hidden and automatic startup is top-level gated', async () => {
  const [javascript, stylesheet] = await Promise.all([
    readFile(new URL('./nearby.js', import.meta.url), 'utf8'),
    readFile(new URL('./nearby.css', import.meta.url), 'utf8'),
  ]);
  assert.match(stylesheet, /\.shell\s*\{[^}]*visibility:\s*hidden/s);
  assert.match(stylesheet, /html\.approval-top-level \.shell\s*\{[^}]*visibility:\s*visible/s);
  assert.match(javascript, /if \(revealTopLevelPage\(window, document\.documentElement\)\) \{/);
  assert.match(javascript, /export async function main\(\) \{\s*if \(typeof window !== 'undefined' && !isTopLevelContext\(window\)\) return;/s);
});
