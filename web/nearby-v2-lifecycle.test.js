import assert from 'node:assert/strict';
import test from 'node:test';

import {
  initialIndeterminateMessage,
  initialRejectionMessage,
  sessionFailureMessage,
  terminatePhaseForPagehide,
} from './nearby-v2.js';

function fakeSession() {
  const sent = [];
  let closed = false;
  return {
    sent,
    send(message) { sent.push(message); },
    close() { closed = true; },
    isOpen() { return !closed; },
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
  assert.deepEqual(session.sent, [{ v: 3, type: 'done' }]);
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
  assert.deepEqual(session.sent, [{ v: 3, type: 'sas-phone-rejected' }]);
  assert.equal(session.closed, true);
});

test('pagehide destroys a held assertion before rejecting pairing', () => {
  const session = fakeSession();
  const releaseNonce = new Uint8Array(32).fill(7);
  const prfFirst = new Uint8Array(32).fill(9);
  terminatePhaseForPagehide({
    kind: 'pairing-held',
    data: {
      kind: 'assertion',
      session,
      releaseNonce,
      result: { prfFirst },
    },
  });
  assert.deepEqual(releaseNonce, new Uint8Array(32));
  assert.deepEqual(prfFirst, new Uint8Array(32));
  assert.deepEqual(session.sent, [{ v: 3, type: 'sas-phone-rejected' }]);
  assert.equal(session.closed, true);
});

test('identity storage failure is not described as an identity mismatch', () => {
  const registration = initialRejectionMessage('identity-store-unavailable', true);
  const assertion = initialRejectionMessage('identity-store-unavailable', false);
  assert.match(registration, /could not save the trusted identity/i);
  assert.match(registration, /passkey may have been created/i);
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
