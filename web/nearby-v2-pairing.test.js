import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import { ProtocolError, encodeBase64URL } from './nearby-v2-protocol.js';
import { requestPairingRelease } from './nearby-v2-pairing.js';

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function fixture() {
  const incoming = deferred();
  const sent = [];
  const verified = [];
  const releaseNonce = new Uint8Array(32).fill(6);
  const session = {
    send: message => sent.push(message),
    next: timeoutMs => {
      assert.equal(timeoutMs, 1234);
      return incoming.promise;
    },
  };
  const verifier = {
    async verifyPairingRelease(fields) {
      verified.push(fields);
    },
  };
  const fields = {
    session,
    verifier,
    sessionBinding: new Uint8Array(32).fill(4),
    sasDigest: new Uint8Array(32).fill(5),
    request: { kind: 'register' },
    releaseNonce,
    timeoutMs: 1234,
  };
  return { fields, incoming, sent, verified, releaseNonce };
}

test('withholds the held result while only announcing phone completion', async () => {
  const { fields, incoming, sent, verified, releaseNonce } = fixture();
  let settled = false;
  const decisionPromise = requestPairingRelease(fields).then(value => {
    settled = true;
    return value;
  });
  await Promise.resolve();

  assert.equal(settled, false);
  assert.deepEqual(sent, [{
    v: 3,
    type: 'sas-phone-complete',
    releaseNonce: encodeBase64URL(releaseNonce),
  }]);
  assert.equal(sent.some(message => /result$/.test(message.type)), false);
  assert.equal(verified.length, 0);

  const signature = new Uint8Array(64).fill(7);
  incoming.resolve({
    v: 3,
    type: 'sas-cli-accepted',
    releaseNonce: encodeBase64URL(releaseNonce),
    signature: encodeBase64URL(signature),
  });
  const decision = await decisionPromise;
  assert.equal(decision.kind, 'accepted');
  assert.deepEqual(decision.signature, signature);
  assert.equal(verified.length, 1);
  assert.deepEqual(verified[0].releaseNonce, releaseNonce);
});

test('rejects an early or replayed decision for another completion nonce', async () => {
  const { fields, incoming, verified } = fixture();
  const decisionPromise = requestPairingRelease(fields);
  incoming.resolve({
    v: 3,
    type: 'sas-cli-accepted',
    releaseNonce: encodeBase64URL(new Uint8Array(32).fill(9)),
    signature: encodeBase64URL(new Uint8Array(64).fill(7)),
  });
  await assert.rejects(decisionPromise, /different pairing instance/);
  assert.equal(verified.length, 0);
});

test('propagates signature failure and accepts only an exact rejection', async () => {
  const invalid = fixture();
  invalid.fields.verifier.verifyPairingRelease = async () => {
    throw new ProtocolError('invalid pairing release signature');
  };
  const invalidPromise = requestPairingRelease(invalid.fields);
  invalid.incoming.resolve({
    v: 3,
    type: 'sas-cli-accepted',
    releaseNonce: encodeBase64URL(invalid.releaseNonce),
    signature: encodeBase64URL(new Uint8Array(64).fill(7)),
  });
  await assert.rejects(invalidPromise, /invalid pairing release signature/);

  const rejected = fixture();
  const rejectedPromise = requestPairingRelease(rejected.fields);
  rejected.incoming.resolve({
    v: 3,
    type: 'sas-cli-rejected',
    releaseNonce: encodeBase64URL(rejected.releaseNonce),
  });
  assert.deepEqual(await rejectedPromise, { kind: 'rejected' });
  assert.equal(rejected.verified.length, 0);
});

test('the phone has no word-match confirmation control', async () => {
  const html = await readFile(new URL('./nearby.html', import.meta.url), 'utf8');
  const pairing = html.match(/<section class="pairing"[\s\S]*?<\/section>/)?.[0];
  assert.ok(pairing, 'pairing section must exist');
  assert.doesNotMatch(pairing, /<button|They match|match|mismatch/i);
  assert.match(pairing, /confirm them once in the terminal/i);
});
