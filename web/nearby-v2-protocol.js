const encoder = new TextEncoder();

const RID_DOMAIN = encoder.encode('keytap:rendezvous:v3\0');
const OFFER_SIGNATURE_DOMAIN = encoder.encode('keytap:signal-offer:v3\0');
const IDENTITY_SESSION_DOMAIN = encoder.encode('keytap:nearby-identity-session:v2\0');
const IDENTITY_PROOF_DOMAIN = encoder.encode('keytap:nearby-identity-proof:v2\0');
const SAS_CONTEXT_DOMAIN = encoder.encode('keytap:nearby-sas-context:v1\0');
const SAS_COMMIT_DOMAIN = encoder.encode('keytap:nearby-sas-commit:v1\0');
const SAS_DIGEST_DOMAIN = encoder.encode('keytap:nearby-sas-digest:v1\0');
const webCrypto = globalThis.crypto;
const SAS_WORD_LIST_SHA256 = Uint8Array.from([
  0x2f, 0x5e, 0xed, 0x53, 0xa4, 0x72, 0x7b, 0x4b,
  0xf8, 0x88, 0x0d, 0x8f, 0x3f, 0x19, 0x9e, 0xfc,
  0x90, 0xe5, 0x85, 0x03, 0x64, 0x6d, 0x9f, 0xf8,
  0xef, 0xf3, 0xa2, 0xed, 0x3b, 0x24, 0xdb, 0xda,
]);
const ED25519_PKCS8_SEED_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

export class ProtocolError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ProtocolError';
  }
}

/** @param {Uint8Array|ArrayBuffer} value */
export function encodeBase64URL(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/** Decode a canonical, unpadded base64url value. */
export function decodeBase64URL(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new ProtocolError('invalid base64url value');
  }
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  let bytes;
  try {
    bytes = Uint8Array.from(atob(padded), character => character.charCodeAt(0));
  } catch {
    throw new ProtocolError('invalid base64url value');
  }
  if (encodeBase64URL(bytes) !== value) throw new ProtocolError('non-canonical base64url value');
  return bytes;
}

function expectObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ProtocolError(`invalid ${label}`);
  }
  return value;
}

function expectBytes(value, label, length) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 128) {
    throw new ProtocolError(`invalid ${label}`);
  }
  const bytes = decodeBase64URL(value);
  if (bytes.length !== length) throw new ProtocolError(`invalid ${label}`);
  return bytes;
}

/** @param {...Uint8Array} arrays */
function concatBytes(...arrays) {
  const result = new Uint8Array(arrays.reduce((length, array) => length + array.length, 0));
  let offset = 0;
  for (const array of arrays) {
    result.set(array, offset);
    offset += array.length;
  }
  return result;
}

function u64(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new ProtocolError('invalid sequence number');
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(value), false);
  return bytes;
}

function u32(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new ProtocolError('identity proof field is too large');
  }
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

function lengthPrefixed(value) {
  return concatBytes(u32(value.length), value);
}

export async function createNearbySessionBinding(
  cliPublicKey,
  offer,
  answer,
) {
  if (!(cliPublicKey instanceof Uint8Array) || cliPublicKey.length !== 32
      || !(offer instanceof Uint8Array) || !(answer instanceof Uint8Array)) {
    throw new ProtocolError('invalid nearby identity session');
  }
  if (!webCrypto?.subtle) throw new ProtocolError('WebCrypto is unavailable');
  return new Uint8Array(await webCrypto.subtle.digest('SHA-256', concatBytes(
    IDENTITY_SESSION_DOMAIN,
    cliPublicKey,
    u64(offer.length),
    offer,
    u64(answer.length),
    answer,
  )));
}

/** Canonical bytes for the exact request authenticated by first-use SAS. */
export function nearbySasRequestBytes(request) {
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    throw new ProtocolError('invalid SAS request');
  }
  if (request.kind === 'register') {
    return concatBytes(
      new Uint8Array([0]),
      lengthPrefixed(request.challenge),
      lengthPrefixed(request.prfSalt),
      lengthPrefixed(request.userId),
      lengthPrefixed(encoder.encode(request.userName)),
    );
  }
  if (request.kind !== 'assert') throw new ProtocolError('invalid SAS request');
  let identity;
  switch (request.identity?.kind) {
    case 'pairing-any':
      identity = new Uint8Array([0]);
      break;
    case 'pairing-credential':
      identity = concatBytes(
        new Uint8Array([1]),
        lengthPrefixed(request.identity.credentialId),
      );
      break;
    default:
      throw new ProtocolError('invalid SAS identity mode');
  }
  let remember;
  switch (request.remember?.kind) {
    case 'disabled':
      remember = new Uint8Array([0]);
      break;
    case 'available':
      remember = concatBytes(new Uint8Array([1]), u64(request.remember.windowSecs));
      break;
    default:
      throw new ProtocolError('invalid SAS remember mode');
  }
  return concatBytes(
    new Uint8Array([1]),
    lengthPrefixed(request.challenge),
    lengthPrefixed(request.prfSalt),
    lengthPrefixed(request.identitySalt),
    lengthPrefixed(encoder.encode(request.keyName)),
    identity,
    remember,
  );
}

export async function createSasContext(
  sessionBinding,
  request,
) {
  if (!(sessionBinding instanceof Uint8Array) || sessionBinding.length !== 32) {
    throw new ProtocolError('invalid SAS session binding');
  }
  const canonicalRequest = nearbySasRequestBytes(request);
  return new Uint8Array(await webCrypto.subtle.digest('SHA-256', concatBytes(
    SAS_CONTEXT_DOMAIN,
    sessionBinding,
    u64(canonicalRequest.length),
    canonicalRequest,
  )));
}

function sasRole(role) {
  if (role === 'cli') return encoder.encode('cli\0');
  if (role === 'phone') return encoder.encode('phone\0');
  throw new ProtocolError('invalid SAS role');
}

export async function createSasCommitment(
  role,
  context,
  nonce,
) {
  if (!(context instanceof Uint8Array) || context.length !== 32
      || !(nonce instanceof Uint8Array) || nonce.length !== 32) {
    throw new ProtocolError('invalid SAS commitment input');
  }
  return new Uint8Array(await webCrypto.subtle.digest('SHA-256', concatBytes(
    SAS_COMMIT_DOMAIN,
    sasRole(role),
    context,
    nonce,
  )));
}

export async function verifySasCommitment(
  role,
  context,
  nonce,
  expected,
) {
  if (!(expected instanceof Uint8Array) || expected.length !== 32) return false;
  const actual = await createSasCommitment(role, context, nonce);
  let difference = 0;
  for (let index = 0; index < actual.length; index += 1) {
    difference |= actual[index] ^ expected[index];
  }
  return difference === 0;
}

export async function createSasDigest(
  context,
  cliCommitment,
  phoneCommitment,
  cliNonce,
  phoneNonce,
) {
  const values = [context, cliCommitment, phoneCommitment, cliNonce, phoneNonce];
  if (values.some(value => !(value instanceof Uint8Array) || value.length !== 32)) {
    throw new ProtocolError('invalid SAS digest input');
  }
  return new Uint8Array(await webCrypto.subtle.digest('SHA-256', concatBytes(
    SAS_DIGEST_DOMAIN,
    ...values,
  )));
}

export function sasPhrase(digest, words) {
  if (!(digest instanceof Uint8Array) || digest.length !== 32
      || !Array.isArray(words) || words.length !== 2048) {
    throw new ProtocolError('invalid SAS phrase input');
  }
  const first = (digest[0] << 3) | (digest[1] >> 5);
  const second = ((digest[1] & 0x1f) << 6) | (digest[2] >> 2);
  return `${words[first]} ${words[second]}`;
}

export async function parseSasWordList(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length > 32 * 1024) {
    throw new ProtocolError('invalid SAS word list');
  }
  const digest = new Uint8Array(await webCrypto.subtle.digest('SHA-256', bytes));
  let difference = 0;
  for (let index = 0; index < digest.length; index += 1) {
    difference |= digest[index] ^ SAS_WORD_LIST_SHA256[index];
  }
  if (difference !== 0) throw new ProtocolError('unexpected SAS word list');
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new ProtocolError('invalid SAS word list');
  }
  const words = text.trimEnd().split('\n');
  if (words.length !== 2048
      || new Set(words).size !== 2048
      || words.some(word => !/^[a-z]{1,8}$/.test(word))) {
    throw new ProtocolError('invalid SAS word list');
  }
  return Object.freeze(words);
}

/**
 * Canonical bytes signed by the passkey-derived nearby identity. The proof is
 * bound to the fresh QR session and to the exact credential, named PRF result,
 * key name, and submitted public identity.
 */
export function nearbyIdentityProofMessage({
  binding,
  challenge,
  credentialId,
  prfFirst,
  keyName,
  publicKey,
}) {
  const bindingDigest = binding?.digest;
  const byteFields = [bindingDigest, challenge, credentialId, prfFirst, publicKey];
  if (byteFields.some(value => !(value instanceof Uint8Array))) {
    throw new ProtocolError('invalid identity proof field');
  }
  if ((binding.kind !== 'bootstrap-sas' && binding.kind !== 'pinned-session')
      || bindingDigest.length !== 32
      || challenge.length < 16 || challenge.length > 128
      || credentialId.length < 1 || credentialId.length > 1024
      || prfFirst.length !== 32
      || publicKey.length !== 32
      || typeof keyName !== 'string') {
    throw new ProtocolError('invalid identity proof field');
  }
  const name = encoder.encode(keyName);
  if (name.length < 1 || name.length > 128) throw new ProtocolError('invalid identity proof key name');
  return concatBytes(
    IDENTITY_PROOF_DOMAIN,
    new Uint8Array([binding.kind === 'bootstrap-sas' ? 0 : 1]),
    lengthPrefixed(bindingDigest),
    lengthPrefixed(challenge),
    lengthPrefixed(credentialId),
    lengthPrefixed(prfFirst),
    lengthPrefixed(name),
    lengthPrefixed(publicKey),
  );
}

/** Derive and use the stable Ed25519 identity from WebAuthn PRF's second output. */
export async function createNearbyIdentityProof(fields, prfSecond) {
  if (!(prfSecond instanceof Uint8Array) || prfSecond.length !== 32) {
    throw new ProtocolError('invalid identity PRF output');
  }
  if (!webCrypto?.subtle) throw new ProtocolError('WebCrypto is unavailable');

  const pkcs8 = concatBytes(ED25519_PKCS8_SEED_PREFIX, prfSecond);
  try {
    const privateKey = await webCrypto.subtle.importKey(
      'pkcs8',
      pkcs8,
      { name: 'Ed25519' },
      true,
      ['sign'],
    );
    const jwk = await webCrypto.subtle.exportKey('jwk', privateKey);
    if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519' || typeof jwk.x !== 'string') {
      throw new ProtocolError('browser returned an invalid Ed25519 identity');
    }
    const publicKey = decodeBase64URL(jwk.x);
    if (publicKey.length !== 32) throw new ProtocolError('browser returned an invalid Ed25519 identity');
    const message = nearbyIdentityProofMessage({ ...fields, publicKey });
    const signature = new Uint8Array(
      await webCrypto.subtle.sign('Ed25519', privateKey, message),
    );
    if (signature.length !== 64) throw new ProtocolError('browser returned an invalid identity signature');
    return { publicKey, signature };
  } catch (error) {
    if (error instanceof ProtocolError) throw error;
    throw new ProtocolError('this browser cannot create the nearby Ed25519 identity proof');
  } finally {
    pkcs8.fill(0);
  }
}

function offerSignatureMessage(seq, body) {
  return concatBytes(
    OFFER_SIGNATURE_DOMAIN,
    new Uint8Array([3]),
    encoder.encode('cli\0'),
    u64(seq),
    encoder.encode('offer\0'),
    u64(body.length),
    body,
  );
}

/**
 * Build a verifier for the one-time CLI public key carried in the QR fragment.
 * A valid offer signature authenticates the offer's DTLS fingerprint, which
 * in turn authenticates every later data-channel message from the CLI.
 *
 * @param {Uint8Array} cliPublicKeyBytes exactly 32 Ed25519 public-key bytes
 */
export async function createCliOfferVerifier(cliPublicKeyBytes) {
  if (!(cliPublicKeyBytes instanceof Uint8Array) || cliPublicKeyBytes.length !== 32) {
    throw new ProtocolError('invalid nearby CLI public key');
  }
  if (!webCrypto?.subtle) throw new ProtocolError('WebCrypto is unavailable');

  const cliPublicKey = cliPublicKeyBytes.slice();
  const rendezvous = new Uint8Array(
    await webCrypto.subtle.digest('SHA-256', concatBytes(RID_DOMAIN, cliPublicKey)),
  );
  let verificationKey;
  try {
    verificationKey = await webCrypto.subtle.importKey(
      'raw',
      cliPublicKey,
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
  } catch {
    throw new ProtocolError('invalid nearby CLI public key');
  }

  return Object.freeze({
    rendezvousId: encodeBase64URL(rendezvous),
    cliPublicKey,

    /** Verify exact state and signature before returning the offer bytes. */
    async verifyOffer(envelope) {
      if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)
          || envelope.v !== 3
          || envelope.from !== 'cli'
          || envelope.seq !== 0
          || envelope.kind !== 'offer') {
        throw new ProtocolError('unexpected signaling state');
      }
      const keys = Object.keys(envelope).sort();
      const expectedKeys = ['body', 'from', 'kind', 'seq', 'signature', 'v'];
      if (keys.length !== expectedKeys.length
          || keys.some((key, index) => key !== expectedKeys[index])) {
        throw new ProtocolError('invalid signaling envelope');
      }
      const body = decodeBase64URL(envelope.body);
      const signature = decodeBase64URL(envelope.signature);
      if (signature.length !== 64) throw new ProtocolError('invalid offer signature');
      const valid = await webCrypto.subtle.verify(
        'Ed25519',
        verificationKey,
        signature,
        offerSignatureMessage(envelope.seq, body),
      );
      if (!valid) throw new ProtocolError('signaling authentication failed');
      return body;
    },
  });
}

export const CLOUDFLARE_STUN_ONLY = Object.freeze([
  Object.freeze({ urls: Object.freeze(['stun:stun.cloudflare.com:3478']) }),
]);

const CLOUDFLARE_TURN_URLS = Object.freeze([
  'turn:turn.cloudflare.com:3478?transport=udp',
  'turn:turn.cloudflare.com:3478?transport=tcp',
  'turn:turn.cloudflare.com:80?transport=tcp',
  'turns:turn.cloudflare.com:5349?transport=tcp',
  'turns:turn.cloudflare.com:443?transport=tcp',
]);

/**
 * Extract only the short-lived username and credential from Cloudflare's
 * response. ICE URLs are never trusted input: clients use the hardcoded,
 * non-port-53 Cloudflare endpoints above. A forged response is therefore DoS,
 * not a way to redirect ICE to an attacker-controlled host.
 */
export function filterCloudflareIceServers(value) {
  if (!Array.isArray(value)) throw new ProtocolError('invalid TURN response');
  const credentials = value.find(candidate => (
    candidate
    && typeof candidate === 'object'
    && !Array.isArray(candidate)
    && typeof candidate.username === 'string'
    && candidate.username.length > 0
    && candidate.username.length <= 1024
    && typeof candidate.credential === 'string'
    && candidate.credential.length > 0
    && candidate.credential.length <= 4096
  ));
  if (!credentials) throw new ProtocolError('TURN response contained no credentials');
  return [
    { urls: [...CLOUDFLARE_STUN_ONLY[0].urls] },
    {
      urls: [...CLOUDFLARE_TURN_URLS],
      username: credentials.username,
      credential: credentials.credential,
    },
  ];
}
