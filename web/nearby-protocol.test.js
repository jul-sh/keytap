import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  IdentityProofUnavailableError,
  ProtocolError,
  createApproverCipher,
  createNearbyIdentityProof,
  createRegistrationIdentityProof,
  createSasCommitment,
  createSasContext,
  createSasDigest,
  decodeBase64URL,
  encodeBase64URL,
  importEd25519SigningKey,
  nearbyIdentityProofMessage,
  parseCliMessage,
  parseInitialRequest,
  parseSasWordList,
  registrationIdentityProofMessage,
  relayRoomId,
  sasPhrase,
  verifySasCommitment,
} from './nearby-protocol.js';

const encoder = new TextEncoder();
const ROOM_DOMAIN = encoder.encode('keytap:relay-room:v1\0');
const SESSION_DOMAIN = encoder.encode('keytap:relay-session:v1\0');
const CLI_INFO = encoder.encode('keytap:relay-key:v1\0cli-to-approver');
const APPROVER_INFO = encoder.encode('keytap:relay-key:v1\0approver-to-cli');
const BOX_DOMAIN = encoder.encode('keytap:relay-box:v1\0');
const CLI_DIRECTION = encoder.encode('CLI\0');
const APPROVER_DIRECTION = encoder.encode('APP\0');
const IDENTITY_PROOF_DOMAIN = encoder.encode('keytap:nearby-identity-proof:v4\0');
const REGISTRATION_IDENTITY_PROOF_DOMAIN = encoder.encode(
  'keytap:nearby-registration-identity-proof:v1\0',
);
const ED25519_PKCS8_SEED_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');

function concat(...values) {
  return Buffer.concat(values.map(value => Buffer.from(value)));
}

function u64(value) {
  const bytes = Buffer.alloc(8);
  bytes.writeBigUInt64BE(BigInt(value));
  return bytes;
}

function u32(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
}

async function deriveAes(material, binding, info, usage) {
  const hkdf = await crypto.subtle.importKey('raw', material, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: binding, info },
    hkdf,
    { name: 'AES-GCM', length: 256 },
    false,
    [usage],
  );
}

async function cliPeer() {
  const pair = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits'],
  );
  const publicKey = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  return { pair, publicKey };
}

async function cliChannel(peer, approverHello) {
  assert.equal(approverHello.length, 66);
  assert.equal(approverHello[0], 0x01);
  const approverPublic = approverHello.subarray(1);
  const approverKey = await crypto.subtle.importKey(
    'raw',
    approverPublic,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    [],
  );
  const shared = new Uint8Array(await crypto.subtle.deriveBits(
    { name: 'ECDH', public: approverKey },
    peer.pair.privateKey,
    256,
  ));
  const binding = new Uint8Array(await crypto.subtle.digest(
    'SHA-256',
    concat(SESSION_DOMAIN, peer.publicKey, approverPublic),
  ));
  const outgoing = await deriveAes(shared, binding, CLI_INFO, 'encrypt');
  const incoming = await deriveAes(shared, binding, APPROVER_INFO, 'decrypt');
  shared.fill(0);
  let outgoingSequence = 0n;
  let incomingSequence = 0n;

  return {
    binding,
    async seal(value) {
      const sequence = outgoingSequence;
      const plaintext = encoder.encode(JSON.stringify(value));
      const ciphertext = new Uint8Array(await crypto.subtle.encrypt({
        name: 'AES-GCM',
        iv: concat(CLI_DIRECTION, u64(sequence)),
        additionalData: concat(BOX_DOMAIN, binding, CLI_DIRECTION, u64(sequence)),
      }, outgoing, plaintext));
      outgoingSequence += 1n;
      return new Uint8Array(concat(Uint8Array.of(0x02), u64(sequence), ciphertext));
    },
    async open(frame) {
      assert.equal(frame[0], 0x02);
      const sequence = new DataView(frame.buffer, frame.byteOffset + 1, 8).getBigUint64(0);
      assert.equal(sequence, incomingSequence);
      const plaintext = await crypto.subtle.decrypt({
        name: 'AES-GCM',
        iv: concat(APPROVER_DIRECTION, u64(sequence)),
        additionalData: concat(BOX_DOMAIN, binding, APPROVER_DIRECTION, u64(sequence)),
      }, incoming, frame.subarray(9));
      incomingSequence += 1n;
      return JSON.parse(new TextDecoder().decode(plaintext));
    },
  };
}

test('derives the exact room, ECDH binding, and directional relay boxes', async () => {
  const cli = await cliPeer();
  const expectedRoom = createHash('sha256').update(ROOM_DOMAIN).update(cli.publicKey).digest('base64url');
  assert.equal(await relayRoomId(cli.publicKey), expectedRoom);

  const approver = await createApproverCipher(cli.publicKey);
  const peer = await cliChannel(cli, approver.hello);
  assert.deepEqual(approver.sessionBinding, peer.binding);

  const request = { type: 'request', request: { kind: 'register' } };
  const requestBytes = encoder.encode(JSON.stringify(request));
  const opened = await approver.open(await peer.seal(request));
  assert.deepEqual(opened.value, request);
  assert.deepEqual(opened.bytes, requestBytes);

  const confirmed = { type: 'sas-approver-confirmed' };
  assert.deepEqual(await peer.open(await approver.seal(confirmed)), confirmed);
});

test('relay boxes reject tampering, replay, wrong direction, and sequence gaps', async () => {
  const cli = await cliPeer();
  const approver = await createApproverCipher(cli.publicKey);
  const peer = await cliChannel(cli, approver.hello);
  const first = await peer.seal({ type: 'request', request: { kind: 'register' } });
  const changed = first.slice();
  changed[changed.length - 1] ^= 1;
  await assert.rejects(approver.open(changed), /authentication failed/i);

  const freshApprover = await createApproverCipher(cli.publicKey);
  const freshPeer = await cliChannel(cli, freshApprover.hello);
  const valid = await freshPeer.seal({ type: 'request', request: { kind: 'register' } });
  await freshApprover.open(valid);
  await assert.rejects(freshApprover.open(valid), /sequence/i);

  const gapApprover = await createApproverCipher(cli.publicKey);
  const gapPeer = await cliChannel(cli, gapApprover.hello);
  await gapPeer.seal({ skipped: true });
  const second = await gapPeer.seal({ type: 'request' });
  await assert.rejects(gapApprover.open(second), /sequence/i);

  const reflectedApprover = await createApproverCipher(cli.publicKey);
  await assert.rejects(
    reflectedApprover.open(await reflectedApprover.seal({ reflected: true })),
    /authentication failed/i,
  );
});

test('rejects malformed P-256 keys and relay plaintext', async () => {
  await assert.rejects(createApproverCipher(new Uint8Array(32)), /public key/i);
  await assert.rejects(createApproverCipher(new Uint8Array(65).fill(4)), /public key/i);

  const cli = await cliPeer();
  const approver = await createApproverCipher(cli.publicKey);
  const peer = await cliChannel(cli, approver.hello);
  const bad = await peer.seal(['not', 'an', 'object']);
  await assert.rejects(approver.open(bad), /not an object/i);
});

test('SAS binds the exact request plaintext and preserves commit-reveal ordering', async () => {
  const binding = new Uint8Array(32).fill(7);
  const request = encoder.encode('{"type":"request","request":{"kind":"register"}}');
  const context = await createSasContext(binding, request);
  const changed = await createSasContext(binding, concat(request, encoder.encode(' ')));
  assert.notDeepEqual(context, changed);

  const cliNonce = new Uint8Array(32).fill(1);
  const approverNonce = new Uint8Array(32).fill(2);
  const cliCommitment = await createSasCommitment('cli', context, cliNonce);
  const approverCommitment = await createSasCommitment('approver', context, approverNonce);
  assert.equal(await verifySasCommitment('cli', context, cliNonce, cliCommitment), true);
  assert.equal(await verifySasCommitment('approver', context, cliNonce, approverCommitment), false);
  const digest = await createSasDigest(
    context,
    cliCommitment,
    approverCommitment,
    cliNonce,
    approverNonce,
  );
  const words = await parseSasWordList(new Uint8Array(
    await readFile(new URL('./nearby-sas-words.txt', import.meta.url)),
  ));
  assert.match(sasPhrase(digest, words), /^[a-z]{1,8} [a-z]{1,8}$/);
});

async function deriveEd25519PublicKey(seed) {
  const privateKey = createPrivateKey({
    key: concat(ED25519_PKCS8_SEED_PREFIX, seed),
    format: 'der',
    type: 'pkcs8',
  });
  const spki = createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
  return new Uint8Array(spki.subarray(spki.length - 32));
}

test('assertion identity modes bind first pairing to SAS and later use to the exact invitation', async () => {
  const identitySeed = new Uint8Array(32).fill(9);
  const sessionBinding = new Uint8Array(32).fill(3);
  const requestFrameBytes = encoder.encode('{"type":"request","request":{"kind":"assert"}}');
  const fields = {
    binding: { kind: 'pinned-identity', sessionBinding, requestFrameBytes },
    challenge: new Uint8Array(32).fill(4),
    credentialId: encoder.encode('credential'),
    prfFirst: new Uint8Array(32).fill(5),
    keyName: 'deploy',
    disposition: 'remember',
  };
  const proof = await createNearbyIdentityProof(fields, identitySeed, deriveEd25519PublicKey);
  const message = nearbyIdentityProofMessage({ ...fields, publicKey: proof.publicKey });
  const publicKey = createPublicKey({
    key: concat(Buffer.from('302a300506032b6570032100', 'hex'), proof.publicKey),
    format: 'der',
    type: 'spki',
  });
  assert.equal(verify(null, message, publicKey, proof.signature), true);
  assert.equal(verify(
    null,
    nearbyIdentityProofMessage({ ...fields, disposition: 'once', publicKey: proof.publicKey }),
    publicKey,
    proof.signature,
  ), false);
  assert.equal(verify(
    null,
    nearbyIdentityProofMessage({
      ...fields,
      binding: {
        ...fields.binding,
        requestFrameBytes: concat(requestFrameBytes, encoder.encode(' ')),
      },
      publicKey: proof.publicKey,
    }),
    publicKey,
    proof.signature,
  ), false);

  const firstPairDigest = new Uint8Array(32).fill(8);
  const firstPair = nearbyIdentityProofMessage({
    ...fields,
    binding: { kind: 'first-pair-sas', digest: firstPairDigest },
    publicKey: proof.publicKey,
  });
  const pinnedIdentity = message;
  assert.deepEqual(
    Buffer.from(firstPair.subarray(0, IDENTITY_PROOF_DOMAIN.length + 1 + 4 + 32)),
    concat(IDENTITY_PROOF_DOMAIN, Uint8Array.of(0), u32(32), firstPairDigest),
  );
  const directPrefixLength = IDENTITY_PROOF_DOMAIN.length
    + 1 + 4 + sessionBinding.length + 4 + requestFrameBytes.length;
  assert.deepEqual(
    Buffer.from(pinnedIdentity.subarray(0, directPrefixLength)),
    concat(
      IDENTITY_PROOF_DOMAIN,
      Uint8Array.of(1),
      u32(32),
      sessionBinding,
      u32(requestFrameBytes.length),
      requestFrameBytes,
    ),
  );

  const signingKey = await importEd25519SigningKey(identitySeed);
  assert.equal(signingKey.extractable, false);

  await assert.rejects(
    createNearbyIdentityProof(fields, identitySeed, async () => {
      throw new Error('Ed25519 unavailable');
    }),
    IdentityProofUnavailableError,
  );
});

test('registration pins a PRF-derived identity to the confirmed first pair', async () => {
  const identitySeed = new Uint8Array(32).fill(7);
  const fields = {
    sasDigest: new Uint8Array(32).fill(0x42),
    challenge: new Uint8Array(32).fill(0x24),
    credentialId: encoder.encode('credential-one'),
  };
  const proof = await createRegistrationIdentityProof(
    fields,
    identitySeed,
    deriveEd25519PublicKey,
  );
  const message = registrationIdentityProofMessage({ ...fields, publicKey: proof.publicKey });
  assert.equal(
    encodeBase64URL(proof.publicKey),
    '6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw',
  );
  assert.equal(
    encodeBase64URL(proof.signature),
    '-SgBnVv-F9ZDxFkl6jp85kwLRc43U2z-NGVb5gVlz3b0HcNbU8LhShwmgcNAEotlCHt4IrOBJ_iQyuMpz6sYDw',
  );
  assert.equal(
    encodeBase64URL(message),
    'a2V5dGFwOm5lYXJieS1yZWdpc3RyYXRpb24taWRlbnRpdHktcHJvb2Y6djEAAAAAIEJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCAAAAICQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkAAAADmNyZWRlbnRpYWwtb25lAAAAIOpKbGPinFIKvvVQexMuxfmVR3auvr57kkIe6mkURtIs',
  );
  assert.deepEqual(
    Buffer.from(message),
    concat(
      REGISTRATION_IDENTITY_PROOF_DOMAIN,
      u32(32),
      fields.sasDigest,
      u32(32),
      fields.challenge,
      u32(fields.credentialId.length),
      fields.credentialId,
      u32(32),
      proof.publicKey,
    ),
  );
  const publicKey = createPublicKey({
    key: concat(Buffer.from('302a300506032b6570032100', 'hex'), proof.publicKey),
    format: 'der',
    type: 'spki',
  });
  assert.equal(verify(null, message, publicKey, proof.signature), true);
  assert.equal(verify(
    null,
    registrationIdentityProofMessage({
      ...fields,
      credentialId: concat(fields.credentialId, Uint8Array.of(0)),
      publicKey: proof.publicKey,
    }),
    publicKey,
    proof.signature,
  ), false);
});

const B16 = Buffer.alloc(16).toString('base64url');
const B32 = Buffer.alloc(32).toString('base64url');

function assertionRequest(identity = { kind: 'pinned', credentialId: 'AQ' }) {
  return {
    type: 'request',
    request: {
      kind: 'assert',
      challenge: B16,
      prfSalt: B32,
      identitySalt: B32,
      identity,
      keyName: 'default',
      storage: 'choose',
    },
  };
}

test('request and CLI unions reject unknown or state-inappropriate fields', () => {
  assert.equal(parseInitialRequest(assertionRequest()).kind, 'assert');
  assert.equal(parseInitialRequest(assertionRequest({ kind: 'pairing-any' })).identity.kind, 'pairing-any');
  const registration = {
    type: 'request',
    request: {
      kind: 'register',
      challenge: B16,
      identitySalt: B32,
      userId: 'AQ',
      userName: 'nearby',
    },
  };
  assert.equal(parseInitialRequest(registration).kind, 'register');
  assert.throws(() => parseInitialRequest({
    ...registration,
    request: { ...registration.request, prfSalt: B32 },
  }), /invalid/i);
  for (const invalid of [
    { ...assertionRequest(), extra: true },
    { ...assertionRequest(), request: { ...assertionRequest().request, extra: true } },
    {
      ...assertionRequest(),
      request: {
        ...assertionRequest().request,
        identity: { kind: 'pinned', credentialId: 'AQ', extra: true },
      },
    },
  ]) {
    assert.throws(() => parseInitialRequest(invalid), /invalid/i);
  }

  for (const [message, expected] of [
    [{ type: 'sas-cli-commit', commitment: B32 }, 'sas-cli-commit'],
    [{ type: 'sas-cli-reveal', nonce: B32 }, 'sas-cli-reveal'],
    [{ type: 'sas-cli-confirmed' }, 'sas-cli-confirmed'],
    [{ type: 'initial-accepted' }, 'initial-accepted'],
    [{ type: 'assertion-accepted', storage: 'stored' }, 'assertion-accepted'],
  ]) {
    assert.deepEqual(parseCliMessage(message, expected), message);
    assert.throws(() => parseCliMessage({ ...message, extra: true }, expected), /invalid/i);
  }
  assert.throws(
    () => parseCliMessage({ type: 'sas-cli-rejected', extra: true }, 'sas-cli-confirmed'),
    /invalid/i,
  );
});

test('base64url is canonical and the approval surface names only the encrypted relay', async () => {
  assert.deepEqual(decodeBase64URL('AA-_'), new Uint8Array([0, 15, 191]));
  assert.equal(encodeBase64URL(new Uint8Array([0, 15, 191])), 'AA-_');
  for (const value of ['AA==', 'AA+', 'A']) {
    assert.throws(() => decodeBase64URL(value), ProtocolError);
  }

  const files = await Promise.all([
    readFile(new URL('./nearby.html', import.meta.url), 'utf8'),
    readFile(new URL('./nearby.js', import.meta.url), 'utf8'),
    readFile(new URL('./nearby-protocol.js', import.meta.url), 'utf8'),
  ]);
  const source = files.join('\n');
  assert.match(source, /end-to-end encrypted relay/i);
  assert.match(files[0], /application messages only as end-to-end encrypted ciphertext/i);
  assert.match(files[0], /name="referrer" content="no-referrer"/);
});
