const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const webCrypto = globalThis.crypto;

const ROOM_DOMAIN = encoder.encode('keytap:relay-room:v1\0');
const SESSION_DOMAIN = encoder.encode('keytap:relay-session:v1\0');
const CLI_KEY_INFO = encoder.encode('keytap:relay-key:v1\0cli-to-approver');
const APPROVER_KEY_INFO = encoder.encode('keytap:relay-key:v1\0approver-to-cli');
const BOX_DOMAIN = encoder.encode('keytap:relay-box:v1\0');
const CLI_DIRECTION = encoder.encode('CLI\0');
const APPROVER_DIRECTION = encoder.encode('APP\0');
const SAS_CONTEXT_DOMAIN = encoder.encode('keytap:nearby-sas-context:v1\0');
const SAS_COMMIT_DOMAIN = encoder.encode('keytap:nearby-sas-commit:v1\0');
const SAS_DIGEST_DOMAIN = encoder.encode('keytap:nearby-sas-digest:v1\0');
const IDENTITY_PROOF_DOMAIN = encoder.encode('keytap:nearby-identity-proof:v5\0');
const REGISTRATION_IDENTITY_PROOF_DOMAIN = encoder.encode(
  'keytap:nearby-registration-identity-proof:v1\0',
);
const HELLO_TAG = 0x01;
const BOX_TAG = 0x02;
const MAX_BOX_BYTES = 16 * 1024;
const MAX_PLAINTEXT_BYTES = MAX_BOX_BYTES - 1 - 8 - 16;
const ED25519_PKCS8_SEED_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);
const SAS_WORD_LIST_SHA256 = Uint8Array.from([
  0x2f, 0x5e, 0xed, 0x53, 0xa4, 0x72, 0x7b, 0x4b,
  0xf8, 0x88, 0x0d, 0x8f, 0x3f, 0x19, 0x9e, 0xfc,
  0x90, 0xe5, 0x85, 0x03, 0x64, 0x6d, 0x9f, 0xf8,
  0xef, 0xf3, 0xa2, 0xed, 0x3b, 0x24, 0xdb, 0xda,
]);

export class ProtocolError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ProtocolError';
  }
}

export class InitialRejectionError extends ProtocolError {
  constructor(reason) {
    super(`the CLI rejected the passkey identity (${reason})`);
    this.name = 'InitialRejectionError';
    this.reason = reason;
  }
}

export class InitialIndeterminateError extends ProtocolError {
  constructor(reason) {
    super(`the CLI could not confirm durable identity storage (${reason})`);
    this.name = 'InitialIndeterminateError';
    this.reason = reason;
  }
}

export class PairingRejectedError extends ProtocolError {
  constructor() {
    super('the pairing words were not confirmed');
    this.name = 'PairingRejectedError';
  }
}

export class IdentityProofUnavailableError extends ProtocolError {
  constructor() {
    super('this browser cannot create the nearby passkey identity proof');
    this.name = 'IdentityProofUnavailableError';
  }
}

export function encodeBase64URL(value) {
  const bytes = asBytes(value);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

/** Decode a canonical, unpadded base64url string. */
export function decodeBase64URL(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]*$/.test(value)) {
    throw new ProtocolError('invalid base64url value');
  }
  let bytes;
  try {
    const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
    bytes = Uint8Array.from(atob(padded), character => character.charCodeAt(0));
  } catch {
    throw new ProtocolError('invalid base64url value');
  }
  if (encodeBase64URL(bytes) !== value) {
    throw new ProtocolError('non-canonical base64url value');
  }
  return bytes;
}

function requireCrypto() {
  if (!webCrypto?.subtle) throw new ProtocolError('WebCrypto is unavailable');
  return webCrypto.subtle;
}

function asBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  throw new ProtocolError('invalid binary value');
}

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
  const integer = typeof value === 'bigint' ? value : BigInt(value);
  if (integer < 0n || integer > 0xffff_ffff_ffff_ffffn) {
    throw new ProtocolError('invalid sequence number');
  }
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, integer, false);
  return bytes;
}

function u32(value) {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
    throw new ProtocolError('field is too large');
  }
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

function lengthPrefixed(value) {
  return concatBytes(u32(value.length), value);
}

function validateCliPublicKey(value) {
  const bytes = asBytes(value);
  if (bytes.length !== 65 || bytes[0] !== 0x04) {
    throw new ProtocolError('invalid nearby CLI public key');
  }
  return bytes;
}

export async function relayRoomId(cliPublicKey) {
  const publicKey = validateCliPublicKey(cliPublicKey);
  const digest = await requireCrypto().digest('SHA-256', concatBytes(ROOM_DOMAIN, publicKey));
  return encodeBase64URL(digest);
}

function relayNonce(direction, sequence) {
  return concatBytes(direction, u64(sequence));
}

function relayAad(sessionBinding, direction, sequence) {
  return concatBytes(BOX_DOMAIN, sessionBinding, direction, u64(sequence));
}

function expectJsonObject(bytes) {
  let text;
  try {
    text = decoder.decode(bytes);
  } catch {
    throw new ProtocolError('relay plaintext is not UTF-8');
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    throw new ProtocolError('relay plaintext is not JSON');
  }
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ProtocolError('relay plaintext is not an object');
  }
  return { value, bytes: bytes.slice() };
}

/**
 * Create the approver half of one relay channel. The QR public key authenticates
 * the CLI's ECDH key; possession of either ephemeral private key is required to
 * open any application message relayed by the service.
 */
export async function createApproverCipher(cliPublicKey) {
  const subtle = requireCrypto();
  const cliPublic = validateCliPublicKey(cliPublicKey).slice();
  let cliKey;
  let approverPair;
  try {
    cliKey = await subtle.importKey(
      'raw',
      cliPublic,
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      [],
    );
    approverPair = await subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-256' },
      false,
      ['deriveBits'],
    );
  } catch {
    throw new ProtocolError('invalid nearby CLI public key');
  }

  const approverPublic = new Uint8Array(await subtle.exportKey('raw', approverPair.publicKey));
  if (approverPublic.length !== 65 || approverPublic[0] !== 0x04) {
    throw new ProtocolError('could not create the nearby encryption key');
  }
  const sessionBinding = new Uint8Array(await subtle.digest(
    'SHA-256',
    concatBytes(SESSION_DOMAIN, cliPublic, approverPublic),
  ));
  const shared = new Uint8Array(await subtle.deriveBits(
    { name: 'ECDH', public: cliKey },
    approverPair.privateKey,
    256,
  ));

  let incomingKey;
  let outgoingKey;
  try {
    const material = await subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    const parameters = info => ({
      name: 'HKDF',
      hash: 'SHA-256',
      salt: sessionBinding,
      info,
    });
    incomingKey = await subtle.deriveKey(
      parameters(CLI_KEY_INFO),
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    );
    outgoingKey = await subtle.deriveKey(
      parameters(APPROVER_KEY_INFO),
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt'],
    );
  } finally {
    shared.fill(0);
  }

  const hello = concatBytes(new Uint8Array([HELLO_TAG]), approverPublic);
  let incomingSequence = 0n;
  let outgoingSequence = 0n;
  let incomingChain = Promise.resolve();
  let outgoingChain = Promise.resolve();

  const openNext = async value => {
    const frame = asBytes(value);
    if (frame.length < 1 + 8 + 16 || frame.length > MAX_BOX_BYTES || frame[0] !== BOX_TAG) {
      throw new ProtocolError('invalid relay box');
    }
    const sequence = new DataView(frame.buffer, frame.byteOffset + 1, 8).getBigUint64(0, false);
    if (sequence !== incomingSequence) throw new ProtocolError('unexpected relay sequence');
    let plaintext;
    try {
      plaintext = new Uint8Array(await subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: relayNonce(CLI_DIRECTION, sequence),
          additionalData: relayAad(sessionBinding, CLI_DIRECTION, sequence),
          tagLength: 128,
        },
        incomingKey,
        frame.subarray(9),
      ));
    } catch {
      throw new ProtocolError('relay authentication failed');
    }
    if (plaintext.length > MAX_PLAINTEXT_BYTES) throw new ProtocolError('relay message is too large');
    const decoded = expectJsonObject(plaintext);
    incomingSequence += 1n;
    return decoded;
  };

  const sealNext = async value => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      throw new ProtocolError('relay message must be an object');
    }
    const plaintext = encoder.encode(JSON.stringify(value));
    if (plaintext.length > MAX_PLAINTEXT_BYTES) throw new ProtocolError('relay message is too large');
    const sequence = outgoingSequence;
    const ciphertext = new Uint8Array(await subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: relayNonce(APPROVER_DIRECTION, sequence),
        additionalData: relayAad(sessionBinding, APPROVER_DIRECTION, sequence),
        tagLength: 128,
      },
      outgoingKey,
      plaintext,
    ));
    outgoingSequence += 1n;
    return concatBytes(new Uint8Array([BOX_TAG]), u64(sequence), ciphertext);
  };

  return Object.freeze({
    hello,
    sessionBinding: sessionBinding.slice(),
    open(value) {
      const next = incomingChain.then(() => openNext(value));
      incomingChain = next;
      return next;
    },
    seal(value) {
      const next = outgoingChain.then(() => sealNext(value));
      outgoingChain = next;
      return next;
    },
  });
}

function expectObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new ProtocolError(`invalid ${label}`);
  }
  return value;
}

function hasExactKeys(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value).sort();
  const wanted = [...expected].sort();
  return keys.length === wanted.length && keys.every((key, index) => key === wanted[index]);
}

function expectExactObject(value, expectedKeys, label) {
  const object = expectObject(value, label);
  if (!hasExactKeys(object, expectedKeys)) throw new ProtocolError(`invalid ${label}`);
  return object;
}

function expectString(value, label, maxLength = 256) {
  if (typeof value !== 'string' || value.length === 0 || value.length > maxLength) {
    throw new ProtocolError(`invalid ${label}`);
  }
  return value;
}

function expectBytes(value, label, minimum, maximum) {
  const encoded = expectString(value, label, Math.ceil(maximum * 4 / 3) + 4);
  const bytes = decodeBase64URL(encoded);
  if (bytes.length < minimum || bytes.length > maximum) throw new ProtocolError(`invalid ${label}`);
  return bytes;
}

function parseIdentityMode(value) {
  const identity = expectObject(value, 'identity mode');
  switch (identity.kind) {
    case 'pairing-any':
      expectExactObject(identity, ['kind'], 'identity mode');
      return { kind: 'pairing-any' };
    case 'pairing-credential':
      expectExactObject(identity, ['kind', 'credentialId'], 'identity mode');
      return {
        kind: 'pairing-credential',
        credentialId: expectBytes(identity.credentialId, 'pairing credential ID', 1, 1024),
      };
    case 'pinned':
      expectExactObject(identity, ['kind', 'credentialId'], 'identity mode');
      return {
        kind: 'pinned',
        credentialId: expectBytes(identity.credentialId, 'pinned credential ID', 1, 1024),
      };
    default:
      throw new ProtocolError('invalid identity mode');
  }
}

function parseRequest(value) {
  const request = expectObject(value, 'request');
  switch (request.kind) {
    case 'register':
      expectExactObject(
        request,
        ['kind', 'challenge', 'identitySalt', 'userId', 'userName'],
        'registration request',
      );
      return {
        kind: 'register',
        challenge: expectBytes(request.challenge, 'challenge', 16, 128),
        identitySalt: expectBytes(request.identitySalt, 'identity PRF salt', 32, 32),
        userId: expectBytes(request.userId, 'user ID', 1, 64),
        userName: expectString(request.userName, 'user name'),
      };
    case 'assert':
      expectExactObject(
        request,
        ['kind', 'challenge', 'prfSalt', 'identitySalt', 'identity', 'keyName'],
        'assertion request',
      );
      break;
    default:
      throw new ProtocolError('unsupported nearby request');
  }
  return {
    kind: 'assert',
    challenge: expectBytes(request.challenge, 'challenge', 16, 128),
    prfSalt: expectBytes(request.prfSalt, 'PRF salt', 32, 32),
    identitySalt: expectBytes(request.identitySalt, 'identity PRF salt', 32, 32),
    identity: parseIdentityMode(request.identity),
    keyName: expectString(request.keyName, 'key name'),
  };
}

/** Parse the one request frame accepted at the start of a relay session. */
export function parseInitialRequest(value) {
  const message = expectExactObject(value, ['type', 'request'], 'request message');
  if (message.type !== 'request') throw new ProtocolError('expected a nearby request');
  return parseRequest(message.request);
}

export function isCompletedElsewhereMessage(value) {
  return hasExactKeys(value, ['type']) && value.type === 'completed-elsewhere';
}

/** Parse a CLI message expected by the current exhaustive protocol state. */
export function parseCliMessage(value, expectedType) {
  const message = expectObject(value, 'CLI message');
  if (typeof message.type !== 'string') throw new ProtocolError('invalid CLI message');
  if (message.type === 'protocol-error') {
    if (!hasExactKeys(message, ['type', 'code'])
        || (message.code !== 'invalid-message' && message.code !== 'unexpected-message')) {
      throw new ProtocolError('invalid CLI protocol error');
    }
    throw new ProtocolError(`the CLI rejected the request (${message.code})`);
  }
  if (message.type === 'initial-rejected') {
    const reasons = new Set(['identity-mismatch', 'invalid-identity-proof', 'identity-store-unavailable']);
    if (!hasExactKeys(message, ['type', 'reason']) || !reasons.has(message.reason)) {
      throw new ProtocolError('invalid CLI identity rejection');
    }
    throw new InitialRejectionError(message.reason);
  }
  if (message.type === 'initial-indeterminate') {
    if (!hasExactKeys(message, ['type', 'reason'])
        || message.reason !== 'identity-durability-unknown') {
      throw new ProtocolError('invalid CLI identity status');
    }
    throw new InitialIndeterminateError(message.reason);
  }
  if (message.type === 'sas-cli-rejected') {
    if (!hasExactKeys(message, ['type'])) throw new ProtocolError('invalid CLI pairing rejection');
    throw new PairingRejectedError();
  }
  if (message.type !== expectedType) throw new ProtocolError(`expected ${expectedType}`);
  switch (expectedType) {
    case 'sas-cli-commit':
      return expectExactObject(message, ['type', 'commitment'], 'CLI SAS commitment');
    case 'sas-cli-reveal':
      return expectExactObject(message, ['type', 'nonce'], 'CLI SAS reveal');
    case 'sas-cli-confirmed':
    case 'initial-accepted':
    case 'assertion-accepted':
      return expectExactObject(message, ['type'], `${expectedType} message`);
    default:
      throw new ProtocolError('invalid expected CLI message type');
  }
}

/** Bind SAS directly to the exact decrypted request-frame bytes. */
export async function createSasContext(sessionBinding, requestFrameBytes) {
  if (!(sessionBinding instanceof Uint8Array) || sessionBinding.length !== 32) {
    throw new ProtocolError('invalid SAS session binding');
  }
  const requestBytes = asBytes(requestFrameBytes);
  if (requestBytes.length === 0 || requestBytes.length > MAX_PLAINTEXT_BYTES) {
    throw new ProtocolError('invalid SAS request frame');
  }
  return new Uint8Array(await requireCrypto().digest('SHA-256', concatBytes(
    SAS_CONTEXT_DOMAIN,
    sessionBinding,
    u64(requestBytes.length),
    requestBytes,
  )));
}

function sasRole(role) {
  if (role === 'cli') return encoder.encode('cli\0');
  if (role === 'approver') return encoder.encode('approver\0');
  throw new ProtocolError('invalid SAS role');
}

export async function createSasCommitment(role, context, nonce) {
  if (!(context instanceof Uint8Array) || context.length !== 32
      || !(nonce instanceof Uint8Array) || nonce.length !== 32) {
    throw new ProtocolError('invalid SAS commitment input');
  }
  return new Uint8Array(await requireCrypto().digest('SHA-256', concatBytes(
    SAS_COMMIT_DOMAIN,
    sasRole(role),
    context,
    nonce,
  )));
}

export async function verifySasCommitment(role, context, nonce, expected) {
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
  approverCommitment,
  cliNonce,
  approverNonce,
) {
  const values = [context, cliCommitment, approverCommitment, cliNonce, approverNonce];
  if (values.some(value => !(value instanceof Uint8Array) || value.length !== 32)) {
    throw new ProtocolError('invalid SAS digest input');
  }
  return new Uint8Array(await requireCrypto().digest('SHA-256', concatBytes(
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
  const source = asBytes(bytes);
  if (source.length > 32 * 1024) throw new ProtocolError('invalid SAS word list');
  const digest = new Uint8Array(await requireCrypto().digest('SHA-256', source));
  let difference = 0;
  for (let index = 0; index < digest.length; index += 1) {
    difference |= digest[index] ^ SAS_WORD_LIST_SHA256[index];
  }
  if (difference !== 0) throw new ProtocolError('unexpected SAS word list');
  let text;
  try {
    text = decoder.decode(source);
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
 * Canonical bytes signed by the PRF-derived identity. First pairing is bound
 * to the SAS confirmed on both devices. Later pinned assertions are bound
 * directly to the trusted invitation and exact request.
 */
export function nearbyIdentityProofMessage({
  binding,
  challenge,
  credentialId,
  prfFirst,
  keyName,
  publicKey,
}) {
  if (!(challenge instanceof Uint8Array)
      || !(credentialId instanceof Uint8Array)
      || !(prfFirst instanceof Uint8Array)
      || !(publicKey instanceof Uint8Array)
      || challenge.length < 16 || challenge.length > 128
      || credentialId.length < 1 || credentialId.length > 1024
      || prfFirst.length !== 32
      || publicKey.length !== 32
      || typeof keyName !== 'string') {
    throw new ProtocolError('invalid identity proof field');
  }
  const name = encoder.encode(keyName);
  if (name.length < 1 || name.length > 128) throw new ProtocolError('invalid identity proof key name');
  let proofBinding;
  switch (binding?.kind) {
    case 'first-pair-sas': {
      if (!(binding.digest instanceof Uint8Array) || binding.digest.length !== 32) {
        throw new ProtocolError('invalid identity proof field');
      }
      proofBinding = concatBytes(
        new Uint8Array([0]),
        lengthPrefixed(binding.digest),
      );
      break;
    }
    case 'pinned-identity': {
      if (!(binding.sessionBinding instanceof Uint8Array)
          || binding.sessionBinding.length !== 32
          || !(binding.requestFrameBytes instanceof Uint8Array)
          || binding.requestFrameBytes.length === 0
          || binding.requestFrameBytes.length > MAX_PLAINTEXT_BYTES) {
        throw new ProtocolError('invalid identity proof field');
      }
      proofBinding = concatBytes(
        new Uint8Array([1]),
        lengthPrefixed(binding.sessionBinding),
        lengthPrefixed(binding.requestFrameBytes),
      );
      break;
    }
    default:
      throw new ProtocolError('invalid identity proof field');
  }
  return concatBytes(
    IDENTITY_PROOF_DOMAIN,
    proofBinding,
    lengthPrefixed(challenge),
    lengthPrefixed(credentialId),
    lengthPrefixed(prfFirst),
    lengthPrefixed(name),
    lengthPrefixed(publicKey),
  );
}

/** Canonical registration identity pinned by the confirmed first-pair SAS. */
export function registrationIdentityProofMessage({
  sasDigest,
  challenge,
  credentialId,
  publicKey,
}) {
  if (!(sasDigest instanceof Uint8Array) || sasDigest.length !== 32
      || !(challenge instanceof Uint8Array)
      || challenge.length < 16 || challenge.length > 128
      || !(credentialId instanceof Uint8Array)
      || credentialId.length < 1 || credentialId.length > 1024
      || !(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
    throw new ProtocolError('invalid registration identity proof field');
  }
  return concatBytes(
    REGISTRATION_IDENTITY_PROOF_DOMAIN,
    lengthPrefixed(sasDigest),
    lengthPrefixed(challenge),
    lengthPrefixed(credentialId),
    lengthPrefixed(publicKey),
  );
}

/** Import the Ed25519 seed as a non-extractable signing-only key. */
export async function importEd25519SigningKey(identitySeed) {
  if (!(identitySeed instanceof Uint8Array) || identitySeed.length !== 32) {
    throw new ProtocolError('invalid identity PRF output');
  }
  const pkcs8 = concatBytes(ED25519_PKCS8_SEED_PREFIX, identitySeed);
  try {
    return await requireCrypto().importKey(
      'pkcs8',
      pkcs8,
      { name: 'Ed25519' },
      false,
      ['sign'],
    );
  } finally {
    pkcs8.fill(0);
  }
}

async function deriveIdentityPublicKey(identitySeed, publicKeyDeriver) {
  if (typeof publicKeyDeriver !== 'function') {
    throw new IdentityProofUnavailableError();
  }
  let publicKey;
  try {
    publicKey = await publicKeyDeriver(identitySeed);
  } catch {
    throw new IdentityProofUnavailableError();
  }
  if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
    throw new IdentityProofUnavailableError();
  }
  return publicKey.slice();
}

async function createIdentityProof(fields, identitySeed, publicKeyDeriver, messageBuilder) {
  if (!(identitySeed instanceof Uint8Array) || identitySeed.length !== 32) {
    throw new IdentityProofUnavailableError();
  }
  try {
    const privateKey = await importEd25519SigningKey(identitySeed);
    const publicKey = await deriveIdentityPublicKey(identitySeed, publicKeyDeriver);
    const message = messageBuilder({ ...fields, publicKey });
    const signature = new Uint8Array(
      await requireCrypto().sign('Ed25519', privateKey, message),
    );
    if (signature.length !== 64) throw new ProtocolError('invalid identity signature');
    return { publicKey, signature };
  } catch (error) {
    if (error instanceof ProtocolError) throw error;
    throw new IdentityProofUnavailableError();
  }
}

export function createNearbyIdentityProof(fields, identitySeed, publicKeyDeriver) {
  return createIdentityProof(fields, identitySeed, publicKeyDeriver, nearbyIdentityProofMessage);
}

export function createRegistrationIdentityProof(fields, identitySeed, publicKeyDeriver) {
  return createIdentityProof(
    fields,
    identitySeed,
    publicKeyDeriver,
    registrationIdentityProofMessage,
  );
}
