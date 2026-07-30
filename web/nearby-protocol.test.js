import assert from 'node:assert/strict';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
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
  importEd25519SigningKey,
  nearbyIdentityProofMessage,
  nearbySasRequestBytes,
  parseSasWordList,
  sasPhrase,
  turnPasskeyAuthorizationMessage,
  verifySasCommitment,
} from './nearby-protocol.js';

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

test('verifies the Rust-signed CLI offer and compact approval-link key vector', async () => {
  const cliPublicKey = decodeBase64URL('6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw');
  assert.equal(
    encodeBase64URL(cliPublicKey).length,
    43,
  );
  const verifier = await createCliOfferVerifier(cliPublicKey);
  assert.equal(
    verifier.rendezvousId,
    'kEJcshyj36SyT3e3fov2QqlBFMMRquKV0hgfhlqLIeI',
  );
  const envelope = {
    v: 1,
    from: 'cli',
    seq: 0,
    kind: 'offer',
    body: encodeBase64URL(new TextEncoder().encode('{"type":"offer"}')),
    signature: 'VqMHWBIykqAxKHsKgukMdrF99Jq18DxWgwCvaTCMRYN_nuqUYAuk94tKYrxD_tBaOGRUrl71OeRxlnCCoM8qBw',
  };
  assert.deepEqual(envelope, {
    v: 1,
    from: 'cli',
    seq: 0,
    kind: 'offer',
    body: 'eyJ0eXBlIjoib2ZmZXIifQ',
    signature: 'VqMHWBIykqAxKHsKgukMdrF99Jq18DxWgwCvaTCMRYN_nuqUYAuk94tKYrxD_tBaOGRUrl71OeRxlnCCoM8qBw',
  });
  assert.equal(
    new TextDecoder().decode(await verifier.verifyOffer(envelope)),
    '{"type":"offer"}',
  );
  const retry = {
    ...envelope,
    seq: 1,
    signature: 'TgDrSC1EhIxT5cQKGF7JyM4UZpOc7i0TLgYkpYWHbaVFoJXKlvsZaeJoHvAVFyI_8ZAl1EcMragWSbbeHkaGCw',
  };
  assert.equal(
    new TextDecoder().decode(await verifier.verifyOffer(retry, 1)),
    '{"type":"offer"}',
  );
  await assert.rejects(verifier.verifyOffer(retry), /unexpected signaling state/);
  await assert.rejects(verifier.verifyOffer({ ...retry, seq: 2 }, 2), /unexpected signaling state/);
});

test('derives a stable Ed25519 identity and signs the exact nearby result', async () => {
  const cliPublicKey = decodeBase64URL('6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw');
  const sessionBinding = await createNearbySessionBinding(
    cliPublicKey,
    new TextEncoder().encode('offer'),
    new TextEncoder().encode('answer'),
  );
  assert.equal(
    encodeBase64URL(sessionBinding),
    'MiMn0rHSnUJlFMpIE5sBrbshnEo2rHruqNEWOYp_9pk',
  );
  const fields = {
    binding: { kind: 'bootstrap-sas', digest: new Uint8Array(32).fill(0x42) },
    challenge: new Uint8Array(32).fill(0x24),
    credentialId: new TextEncoder().encode('credential-one'),
    prfFirst: new Uint8Array(32).fill(0x11),
    keyName: 'deploy',
    disposition: 'once',
  };
  const identitySeed = new Uint8Array(32).fill(7);
  const proof = await createNearbyIdentityProof(
    fields,
    identitySeed,
    deriveEd25519PublicKeyForTest,
  );

  assert.equal(encodeBase64URL(proof.publicKey), '6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw');
  assert.equal(
    encodeBase64URL(proof.signature),
    'FI5i8E_aJfYVyMSx4mLpyNlkxeShIynByHP6uw_Ynw7E6qMidgretZF9y-lDgXep-ulV4cxDeNBYTwlkdWX6BQ',
  );
  const message = nearbyIdentityProofMessage({ ...fields, publicKey: proof.publicKey });
  const publicKey = await crypto.subtle.importKey(
    'raw',
    proof.publicKey,
    { name: 'Ed25519' },
    false,
    ['verify'],
  );
  assert.equal(await crypto.subtle.verify('Ed25519', publicKey, proof.signature, message), true);

  const changedName = nearbyIdentityProofMessage({
    ...fields,
    keyName: 'production',
    publicKey: proof.publicKey,
  });
  assert.equal(await crypto.subtle.verify('Ed25519', publicKey, proof.signature, changedName), false);

  const changedDisposition = nearbyIdentityProofMessage({
    ...fields,
    disposition: 'remember',
    publicKey: proof.publicKey,
  });
  assert.equal(await crypto.subtle.verify('Ed25519', publicKey, proof.signature, changedDisposition), false);
});

test('matches the passkey TURN authorization interop vector', async () => {
  assert.equal(
    Buffer.from(TURN_IDENTITY_PRF_SALT).toString('hex'),
    '0e77b3886c1dfd2ce68782dc0fa4b6872e75a18dfe28799aab9414b5fd8e249e',
  );
  const fields = {
    rendezvousId: 'A'.repeat(43),
    challenge: decodeBase64URL('ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8'),
    expiresAt: 2_000_000_000_000,
    credentialId: decodeBase64URL('Y3JlZGVudGlhbC1vd25lcg'),
  };
  const proof = await createTurnPasskeyAuthorizationProof(
    fields,
    Uint8Array.from({ length: 32 }, (_, index) => index),
    deriveEd25519PublicKeyForTest,
  );
  assert.equal(
    encodeBase64URL(proof.publicKey),
    'A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg',
  );
  assert.equal(
    encodeBase64URL(proof.signature),
    'Kq7yBsYegNIr5povtDGDpkwPryLT8KFBFKaBZ3Py_y1YaUBO7TGRq7yIrOUB6QWB0BYnU_XsGfCS59a8xRTLBg',
  );
  const verificationKey = await crypto.subtle.importKey(
    'raw', proof.publicKey, { name: 'Ed25519' }, false, ['verify'],
  );
  assert.equal(await crypto.subtle.verify(
    'Ed25519',
    verificationKey,
    proof.signature,
    turnPasskeyAuthorizationMessage({ ...fields, publicKey: proof.publicKey }),
  ), true);
});

test('identity signing keys are non-extractable', async () => {
  const signingKey = await importEd25519SigningKey(new Uint8Array(32).fill(7));
  assert.equal(signingKey.extractable, false);
  await assert.rejects(
    crypto.subtle.exportKey('jwk', signingKey),
    error => error?.name === 'InvalidAccessException',
  );
});

test('matches the Rust commit–reveal SAS vector and pinned word list', async () => {
  const context = new Uint8Array(32).fill(0x42);
  const cliNonce = new Uint8Array(32).fill(0x11);
  const approverNonce = new Uint8Array(32).fill(0x22);
  const cliCommitment = await createSasCommitment('cli', context, cliNonce);
  const approverCommitment = await createSasCommitment('approver', context, approverNonce);
  assert.equal(
    encodeBase64URL(cliCommitment),
    'cvH8dRwfyO39Y_o_PCBXIQPtJ2CgNAF2dCLBJs4YldA',
  );
  assert.equal(
    encodeBase64URL(approverCommitment),
    'uGxkhyyB5CuiWLzkx3yVbtuDET2YFspXyFU24H71YLg',
  );
  assert.equal(await verifySasCommitment('cli', context, cliNonce, cliCommitment), true);
  const changed = cliCommitment.slice();
  changed[0] ^= 1;
  assert.equal(await verifySasCommitment('cli', context, cliNonce, changed), false);

  const digest = await createSasDigest(
    context,
    cliCommitment,
    approverCommitment,
    cliNonce,
    approverNonce,
  );
  assert.equal(
    encodeBase64URL(digest),
    'IAUUgyGRkm-JJ34IUOnGhGCkfqDHlzCZxNtMQFsVQ8w',
  );
  const words = await parseSasWordList(
    new Uint8Array(await readFile(new URL('./nearby-sas-words.txt', import.meta.url))),
  );
  assert.equal(sasPhrase(digest, words), 'cactus chunk');
});

test('canonically binds the exact pairing request', async () => {
  const request = {
    kind: 'assert',
    challenge: new Uint8Array(32).fill(1),
    prfSalt: new Uint8Array(32).fill(2),
    identitySalt: new Uint8Array(32).fill(3),
    keyName: 'deploy',
    identity: { kind: 'pairing-credential', credentialId: new TextEncoder().encode('cred') },
    storage: 'choose',
  };
  assert.equal(
    encodeBase64URL(nearbySasRequestBytes(request)),
    'AQAAACABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAACACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgAAACADAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwAAAAZkZXBsb3kBAAAABGNyZWQA',
  );
  assert.equal(
    encodeBase64URL(await createSasContext(new Uint8Array(32).fill(4), request)),
    '-ttmWQ8-kdx7xyaCzmPOpk7KNSnoYJkNBd_OwlhIxQs',
  );
  assert.throws(
    () => nearbySasRequestBytes({ ...request, storage: { kind: 'choose' } }),
    /storage policy/,
  );
  assert.notDeepEqual(
    nearbySasRequestBytes(request),
    nearbySasRequestBytes({ ...request, storage: 'remember' }),
  );
});

test('binds CLI offer authentication to key, version, state, and body', async () => {
  const verifier = await createCliOfferVerifier(
    decodeBase64URL('6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw'),
  );
  const envelope = {
    v: 1,
    from: 'cli',
    seq: 0,
    kind: 'offer',
    body: 'eyJ0eXBlIjoib2ZmZXIifQ',
    signature: 'VqMHWBIykqAxKHsKgukMdrF99Jq18DxWgwCvaTCMRYN_nuqUYAuk94tKYrxD_tBaOGRUrl71OeRxlnCCoM8qBw',
  };
  await assert.rejects(
    verifier.verifyOffer({ ...envelope, v: 0 }),
    ProtocolError,
  );
  await assert.rejects(
    verifier.verifyOffer({ ...envelope, seq: 1 }),
    ProtocolError,
  );
  await assert.rejects(
    verifier.verifyOffer({ ...envelope, from: 'approver' }),
    ProtocolError,
  );
  await assert.rejects(
    verifier.verifyOffer({ ...envelope, body: encodeBase64URL(new TextEncoder().encode('changed')) }),
    /authentication failed/,
  );
  await assert.rejects(verifier.verifyOffer({ ...envelope, extra: true }), /invalid signaling envelope/);
});

test('accepts canonical base64url only', () => {
  assert.deepEqual(decodeBase64URL('AA'), new Uint8Array([0]));
  assert.throws(() => decodeBase64URL('AA='), ProtocolError);
  assert.throws(() => decodeBase64URL('A'), ProtocolError);
  assert.throws(() => decodeBase64URL('A+'), ProtocolError);
});

test('uses only hardcoded Cloudflare endpoints and omits port 53', () => {
  const servers = filterCloudflareIceServers([
    {
      urls: [
        'turn:attacker.example:3478?transport=udp',
        'turn:turn.cloudflare.com:53?transport=udp',
      ],
      username: 'temporary-user',
      credential: 'temporary-password',
    },
  ]);

  assert.deepEqual(servers[0], { urls: ['stun:stun.cloudflare.com:3478'] });
  assert.equal(servers[1].username, 'temporary-user');
  assert.equal(servers[1].credential, 'temporary-password');
  assert.equal(servers[1].urls.some(url => url.includes('attacker.example')), false);
  assert.equal(servers[1].urls.some(url => /:53(?:\?|$)/.test(url)), false);
});

test('rejects TURN responses without bounded string credentials', () => {
  assert.throws(() => filterCloudflareIceServers([]), ProtocolError);
  assert.throws(
    () => filterCloudflareIceServers([{ urls: 'turn:turn.cloudflare.com:3478?transport=udp' }]),
    ProtocolError,
  );
});

test('the approval page has no word-match confirmation control', async () => {
  const html = await readFile(new URL('./nearby.html', import.meta.url), 'utf8');
  const pairing = html.match(/<section class="pairing"[\s\S]*?<\/section>/)?.[0];
  assert.ok(pairing, 'pairing section must exist');
  assert.doesNotMatch(pairing, /<button|They match|match|mismatch/i);
  assert.match(pairing, /confirm them once in the terminal/i);
});

test('the storage choice is obvious, ordered, and described', async () => {
  const html = await readFile(new URL('./nearby.html', import.meta.url), 'utf8');
  const offer = html.match(/<section class="offer"[\s\S]*?<\/section>/)?.[0];
  assert.ok(offer, 'storage choice section must exist');
  assert.match(offer, /aria-labelledby="offer-heading"/);
  assert.match(offer, /id="done-btn"[^>]*aria-describedby="offer-body offer-hint"[^>]*>Use once</);
  assert.match(offer, /id="remember-btn"[^>]*aria-describedby="offer-body offer-hint"[^>]*>Use and remember</);
  assert.ok(offer.indexOf('Use once') < offer.indexOf('Use and remember'));
});
