import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
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
  nearbyIdentityProofMessage,
  nearbySasRequestBytes,
  parseSasWordList,
  sasPhrase,
  verifySasCommitment,
} from './nearby-v2-protocol.js';

test('verifies the Rust-signed CLI offer and compact public-key QR vector', async () => {
  const cliPublicKey = decodeBase64URL('6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw');
  assert.equal(
    encodeBase64URL(cliPublicKey).length,
    43,
  );
  const verifier = await createCliOfferVerifier(cliPublicKey);
  assert.equal(
    verifier.rendezvousId,
    'MFHH-4Il-dVD-AwsB7c-4kdD25EFZ_aGEczf569GW8U',
  );
  const envelope = {
    v: 3,
    from: 'cli',
    seq: 0,
    kind: 'offer',
    body: encodeBase64URL(new TextEncoder().encode('{"type":"offer"}')),
    signature: 'U2k9m3s7XkIf9QF0ShT4TNY-FzYYAfoF4RX9zLBWoo5TYwS5-oblqKqQdK7mQVxO92UWDTidykN6Nm3vXeWPDg',
  };
  assert.deepEqual(envelope, {
    v: 3,
    from: 'cli',
    seq: 0,
    kind: 'offer',
    body: 'eyJ0eXBlIjoib2ZmZXIifQ',
    signature: 'U2k9m3s7XkIf9QF0ShT4TNY-FzYYAfoF4RX9zLBWoo5TYwS5-oblqKqQdK7mQVxO92UWDTidykN6Nm3vXeWPDg',
  });
  assert.equal(
    new TextDecoder().decode(await verifier.verifyOffer(envelope)),
    '{"type":"offer"}',
  );
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
    '4onRCvmREapRgbR1UvtUZ_AJ0aCKjDR0Q1fWTksrzJY',
  );
  const fields = {
    binding: { kind: 'bootstrap-sas', digest: new Uint8Array(32).fill(0x42) },
    challenge: new Uint8Array(32).fill(0x24),
    credentialId: new TextEncoder().encode('credential-one'),
    prfFirst: new Uint8Array(32).fill(0x11),
    keyName: 'deploy',
  };
  const identitySeed = new Uint8Array(32).fill(7);
  const proof = await createNearbyIdentityProof(fields, identitySeed);

  assert.equal(encodeBase64URL(proof.publicKey), '6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw');
  assert.equal(
    encodeBase64URL(proof.signature),
    'NVy39fNzZCAiPt1NmmwKtykd-vRk9SPzvlxnHd_Lp8smT5qNZZJ5OVvlObjz3hrsPoCVNDtZU4onn_bgPqyFDQ',
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

  const changed = nearbyIdentityProofMessage({
    ...fields,
    keyName: 'production',
    publicKey: proof.publicKey,
  });
  assert.equal(await crypto.subtle.verify('Ed25519', publicKey, proof.signature, changed), false);
});

test('matches the Rust commit–reveal SAS vector and pinned word list', async () => {
  const context = new Uint8Array(32).fill(0x42);
  const cliNonce = new Uint8Array(32).fill(0x11);
  const phoneNonce = new Uint8Array(32).fill(0x22);
  const cliCommitment = await createSasCommitment('cli', context, cliNonce);
  const phoneCommitment = await createSasCommitment('phone', context, phoneNonce);
  assert.equal(
    encodeBase64URL(cliCommitment),
    'cvH8dRwfyO39Y_o_PCBXIQPtJ2CgNAF2dCLBJs4YldA',
  );
  assert.equal(
    encodeBase64URL(phoneCommitment),
    '-uZ7M59bEXt4cV1iqI2FbkKRwgznmHmb79X7bqcHUtk',
  );
  assert.equal(await verifySasCommitment('cli', context, cliNonce, cliCommitment), true);
  const changed = cliCommitment.slice();
  changed[0] ^= 1;
  assert.equal(await verifySasCommitment('cli', context, cliNonce, changed), false);

  const digest = await createSasDigest(
    context,
    cliCommitment,
    phoneCommitment,
    cliNonce,
    phoneNonce,
  );
  assert.equal(
    encodeBase64URL(digest),
    '5ZQGmH1q3mt_ppkjl_U99IdhuExmijw475WdClYiSR0',
  );
  const words = await parseSasWordList(
    new Uint8Array(await readFile(new URL('./nearby-sas-words.txt', import.meta.url))),
  );
  assert.equal(sasPhrase(digest, words), 'tortoise parent');
});

test('canonically binds the exact pairing request', async () => {
  const request = {
    kind: 'assert',
    challenge: new Uint8Array(32).fill(1),
    prfSalt: new Uint8Array(32).fill(2),
    identitySalt: new Uint8Array(32).fill(3),
    keyName: 'deploy',
    identity: { kind: 'pairing-credential', credentialId: new TextEncoder().encode('cred') },
    remember: { kind: 'available', windowSecs: 60 },
  };
  assert.equal(
    encodeBase64URL(nearbySasRequestBytes(request)),
    'AQAAACABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQAAACACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgAAACADAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwAAAAZkZXBsb3kBAAAABGNyZWQBAAAAAAAAADw',
  );
  assert.equal(
    encodeBase64URL(await createSasContext(new Uint8Array(32).fill(4), request)),
    'ov2kOyVpend0ognXvoqine2hW54dYUqDikvCzmw4xqE',
  );
});

test('binds CLI offer authentication to key, version, state, and body', async () => {
  const verifier = await createCliOfferVerifier(
    decodeBase64URL('6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw'),
  );
  const envelope = {
    v: 3,
    from: 'cli',
    seq: 0,
    kind: 'offer',
    body: 'eyJ0eXBlIjoib2ZmZXIifQ',
    signature: 'U2k9m3s7XkIf9QF0ShT4TNY-FzYYAfoF4RX9zLBWoo5TYwS5-oblqKqQdK7mQVxO92UWDTidykN6Nm3vXeWPDg',
  };
  await assert.rejects(
    verifier.verifyOffer({ ...envelope, v: 2 }),
    ProtocolError,
  );
  await assert.rejects(
    verifier.verifyOffer({ ...envelope, seq: 1 }),
    ProtocolError,
  );
  await assert.rejects(
    verifier.verifyOffer({ ...envelope, from: 'phone' }),
    ProtocolError,
  );
  await assert.rejects(
    verifier.verifyOffer({ ...envelope, body: encodeBase64URL(new TextEncoder().encode('changed')) }),
    /authentication failed/,
  );
  await assert.rejects(verifier.verifyOffer({ ...envelope, mac: 'legacy' }), /invalid signaling envelope/);
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

test('the phone has no word-match confirmation control', async () => {
  const html = await readFile(new URL('./nearby.html', import.meta.url), 'utf8');
  const pairing = html.match(/<section class="pairing"[\s\S]*?<\/section>/)?.[0];
  assert.ok(pairing, 'pairing section must exist');
  assert.doesNotMatch(pairing, /<button|They match|match|mismatch/i);
  assert.match(pairing, /confirm them once in the terminal/i);
});
