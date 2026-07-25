import assert from 'node:assert/strict';
import test from 'node:test';

import {
  CLOUDFLARE_STUN_ONLY,
  ProtocolError,
  createNearbyIdentityProof,
  createNearbySessionBinding,
  createSignalAuthenticator,
  decodeBase64URL,
  encodeBase64URL,
  filterCloudflareIceServers,
  isAllowedCloudflareIceUrl,
  nearbyIdentityProofMessage,
} from './nearby-v2-protocol.js';

test('matches the Rust rendezvous, HKDF, and HMAC vector', async () => {
  const capability = new Uint8Array(32).fill(0x42);
  assert.equal(
    encodeBase64URL(capability),
    'QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI',
  );
  const authenticator = await createSignalAuthenticator(capability);
  assert.equal(capability.every(byte => byte === 0), true, 'raw capability is erased after key import');
  assert.equal(
    authenticator.rendezvousId,
    '6_2qUdwr2cvl5omCEB61Ys263Y1nu0TIjppVQPePcUA',
  );
  assert.equal(
    encodeBase64URL(authenticator.capabilityBinding),
    'xSlvZCIXRPywtFu-jlyNoi-WW45oSc_ufGvoTdYb54I',
  );

  const envelope = await authenticator.sign('cli', 0, 'offer', '{"type":"offer"}');
  assert.deepEqual(envelope, {
    v: 2,
    from: 'cli',
    seq: 0,
    kind: 'offer',
    body: 'eyJ0eXBlIjoib2ZmZXIifQ',
    mac: 'FoqM9kpeEx726l8vB0Whib5XjyzePgjWQwBiOFQtZ1E',
  });
  assert.equal(
    new TextDecoder().decode(await authenticator.verify(envelope, 'cli', 0, 'offer')),
    '{"type":"offer"}',
  );

  const answer = await authenticator.sign('phone', 0, 'answer', 'v=0\r\n');
  assert.equal(answer.mac, 'Ob2oYFx6NK-1_LOY2br0jKfkJL-Pcxim2X-mAVRKuao');
});

test('derives a stable Ed25519 identity and signs the exact nearby result', async () => {
  const authenticator = await createSignalAuthenticator(new Uint8Array(32).fill(0x42));
  const sessionBinding = await createNearbySessionBinding(
    authenticator.capabilityBinding,
    new TextEncoder().encode('offer'),
    new TextEncoder().encode('answer'),
  );
  const fields = {
    sessionBinding,
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
    '2UnoDFl5z93sC3gNM7-S3lYG6ckXzu3rIwedCYQvWDU2v-YvpuXlKtOnnLIscb0TSghY6_gUB6zcnTkPZHutAA',
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

test('binds signaling authentication to role, sequence, kind, and body', async () => {
  const authenticator = await createSignalAuthenticator(new Uint8Array(32).fill(7));
  const envelope = await authenticator.sign('phone', 0, 'answer', 'v=0\r\n');

  await assert.rejects(
    authenticator.verify(envelope, 'cli', 0, 'answer'),
    ProtocolError,
  );
  await assert.rejects(
    authenticator.verify(envelope, 'phone', 1, 'answer'),
    ProtocolError,
  );
  await assert.rejects(
    authenticator.verify(envelope, 'phone', 0, 'offer'),
    ProtocolError,
  );
  await assert.rejects(
    authenticator.verify({ ...envelope, body: encodeBase64URL(new TextEncoder().encode('changed')) }, 'phone', 0, 'answer'),
    /authentication failed/,
  );
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
  assert.deepEqual(CLOUDFLARE_STUN_ONLY[0].urls, ['stun:stun.cloudflare.com:3478']);
});

test('Cloudflare URL allowlist is exact', () => {
  assert.equal(isAllowedCloudflareIceUrl('stun:stun.cloudflare.com:3478'), true);
  assert.equal(isAllowedCloudflareIceUrl('turn:turn.cloudflare.com:3478?transport=udp'), true);
  assert.equal(isAllowedCloudflareIceUrl('turns:turn.cloudflare.com:443?transport=tcp'), true);
  assert.equal(isAllowedCloudflareIceUrl('stun:stun.cloudflare.com:53'), false);
  assert.equal(isAllowedCloudflareIceUrl('turn:turn.cloudflare.com:53?transport=udp'), false);
  assert.equal(isAllowedCloudflareIceUrl('turn:evil.example:3478?transport=udp'), false);
  assert.equal(isAllowedCloudflareIceUrl('https://turn.cloudflare.com/'), false);
});

test('rejects TURN responses without bounded string credentials', () => {
  assert.throws(() => filterCloudflareIceServers([]), ProtocolError);
  assert.throws(
    () => filterCloudflareIceServers([{ urls: 'turn:turn.cloudflare.com:3478?transport=udp' }]),
    ProtocolError,
  );
});
