import {
  ProtocolError,
  decodeBase64URL,
  encodeBase64URL,
} from './nearby-v2-protocol.js';

const DEFAULT_DECISION_TIMEOUT_MS = 150_000;

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

function bytesEqual(left, right) {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array)
      || left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

function hasExactKeys(message, expected) {
  const actual = Object.keys(message).sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length
    && actual.every((key, index) => key === sortedExpected[index]);
}

/**
 * Announce that WebAuthn is complete, then authenticate the sole terminal
 * decision. The caller still owns the held credential/PRF result and must not
 * release it unless this function returns `accepted`.
 */
export async function requestPairingRelease({
  session,
  verifier,
  sessionBinding,
  sasDigest,
  request,
  releaseNonce,
  timeoutMs = DEFAULT_DECISION_TIMEOUT_MS,
}) {
  if (!(releaseNonce instanceof Uint8Array) || releaseNonce.length !== 32) {
    throw new ProtocolError('invalid phone release nonce');
  }
  session.send({
    v: 3,
    type: 'sas-phone-complete',
    releaseNonce: encodeBase64URL(releaseNonce),
  });

  const message = expectObject(await session.next(timeoutMs), 'CLI SAS decision');
  if (message.v !== 3 || typeof message.type !== 'string') {
    throw new ProtocolError('invalid CLI SAS decision');
  }
  if (message.type === 'sas-cli-rejected') {
    if (!hasExactKeys(message, ['v', 'type', 'releaseNonce'])) {
      throw new ProtocolError('invalid CLI SAS rejection');
    }
    const nonce = expectBytes(message.releaseNonce, 'CLI release nonce', 32);
    if (!bytesEqual(nonce, releaseNonce)) {
      throw new ProtocolError('CLI rejected a different pairing instance');
    }
    return { kind: 'rejected' };
  }
  if (message.type === 'sas-cli-accepted') {
    if (!hasExactKeys(message, ['v', 'type', 'releaseNonce', 'signature'])) {
      throw new ProtocolError('invalid CLI SAS acceptance');
    }
    const nonce = expectBytes(message.releaseNonce, 'CLI release nonce', 32);
    if (!bytesEqual(nonce, releaseNonce)) {
      throw new ProtocolError('CLI released a different pairing instance');
    }
    const signature = expectBytes(message.signature, 'CLI release signature', 64);
    await verifier.verifyPairingRelease({
      signature,
      sessionBinding,
      sasDigest,
      request,
      releaseNonce,
    });
    return { kind: 'accepted', signature };
  }
  if (message.type === 'protocol-error') {
    throw new ProtocolError('the CLI rejected the pairing protocol');
  }
  throw new ProtocolError('expected CLI SAS decision');
}
