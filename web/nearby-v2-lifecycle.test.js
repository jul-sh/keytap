import assert from 'node:assert/strict';
import test from 'node:test';

import {
  handlePageShow,
  initialIndeterminateMessage,
  initialRejectionMessage,
  sendPairedAssertionResult,
  sendPairedRegistrationResult,
  sessionFailureMessage,
  storageUnavailableMessage,
  terminatePhaseForPagehide,
} from './nearby-v2.js';

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

test('pagehide cancels an in-flight connection generation', () => {
  const controller = new AbortController();
  terminatePhaseForPagehide({ kind: 'connecting', data: { controller } });
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
  assert.deepEqual(session.sent, [{ type: 'sas-phone-rejected' }]);
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
  assert.deepEqual(session.sent, [{ type: 'sas-phone-rejected' }]);
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
    assert.match(elements.alert.textContent, /fresh code/i);
    assert.equal(elements.alert.focused, true);
  } finally {
    if (previousDocument === undefined) delete globalThis.document;
    else globalThis.document = previousDocument;
  }
});
