const encoder = new TextEncoder();

const RID_DOMAIN = encoder.encode('keytap:rendezvous:v2\0');
const MAC_DOMAIN = encoder.encode('keytap:signal:v2\0');
const KEY_INFO_PREFIX = 'keytap:signal-key:v2:';

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

function roleBytes(role) {
  if (role !== 'cli' && role !== 'phone') throw new ProtocolError('invalid signaling role');
  return encoder.encode(role);
}

function kindBytes(kind) {
  if (kind !== 'offer' && kind !== 'answer') throw new ProtocolError('invalid signaling kind');
  return encoder.encode(kind);
}

function transcript(role, seq, kind, body) {
  return concatBytes(
    MAC_DOMAIN,
    roleBytes(role),
    new Uint8Array([0]),
    u64(seq),
    kindBytes(kind),
    new Uint8Array([0]),
    u64(body.length),
    body,
  );
}

/**
 * Build the authenticated signaling context from the one-time QR capability.
 * The raw capability is copied into non-extractable WebCrypto keys and then
 * erased from JavaScript-owned memory.
 *
 * @param {Uint8Array} capabilityBytes exactly 32 random bytes
 * @param {Crypto} webCrypto injectable only for tests
 */
export async function createSignalAuthenticator(capabilityBytes, webCrypto = globalThis.crypto) {
  if (!(capabilityBytes instanceof Uint8Array) || capabilityBytes.length !== 32) {
    throw new ProtocolError('invalid nearby capability');
  }
  if (!webCrypto?.subtle) throw new ProtocolError('WebCrypto is unavailable');

  const secret = capabilityBytes.slice();
  const rendezvous = new Uint8Array(
    await webCrypto.subtle.digest('SHA-256', concatBytes(RID_DOMAIN, secret)),
  );
  const keyMaterial = await webCrypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey']);

  async function deriveKey(role) {
    return webCrypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: rendezvous,
        info: encoder.encode(KEY_INFO_PREFIX + role),
      },
      keyMaterial,
      { name: 'HMAC', hash: 'SHA-256', length: 256 },
      false,
      ['sign', 'verify'],
    );
  }

  const [cliKey, phoneKey] = await Promise.all([deriveKey('cli'), deriveKey('phone')]);
  secret.fill(0);
  capabilityBytes.fill(0);

  const keys = { cli: cliKey, phone: phoneKey };
  return Object.freeze({
    rendezvousId: encodeBase64URL(rendezvous),

    /** @returns {Promise<{v: 2, from: 'cli'|'phone', seq: number, kind: 'offer'|'answer', body: string, mac: string}>} */
    async sign(role, seq, kind, bodyValue) {
      let body;
      if (bodyValue instanceof Uint8Array) {
        body = bodyValue;
      } else if (bodyValue instanceof ArrayBuffer) {
        body = new Uint8Array(bodyValue);
      } else if (typeof bodyValue === 'string') {
        body = encoder.encode(bodyValue);
      } else {
        throw new ProtocolError('invalid signaling body');
      }
      const mac = await webCrypto.subtle.sign('HMAC', keys[role], transcript(role, seq, kind, body));
      return {
        v: 2,
        from: role,
        seq,
        kind,
        body: encodeBase64URL(body),
        mac: encodeBase64URL(mac),
      };
    },

    /** Verify state and HMAC before returning the authenticated body bytes. */
    async verify(envelope, expectedRole, expectedSeq, expectedKind) {
      if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
        throw new ProtocolError('invalid signaling envelope');
      }
      if (envelope.v !== 2
          || envelope.from !== expectedRole
          || envelope.seq !== expectedSeq
          || envelope.kind !== expectedKind) {
        throw new ProtocolError('unexpected signaling state');
      }
      const body = decodeBase64URL(envelope.body);
      const mac = decodeBase64URL(envelope.mac);
      if (mac.length !== 32) throw new ProtocolError('invalid signaling MAC');
      const valid = await webCrypto.subtle.verify(
        'HMAC',
        keys[expectedRole],
        mac,
        transcript(expectedRole, expectedSeq, expectedKind, body),
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

export function isAllowedCloudflareIceUrl(value) {
  if (typeof value !== 'string') return false;
  const match = /^(stun|turn|turns):([a-z0-9.-]+):(\d+)(?:\?transport=(udp|tcp))?$/i.exec(value);
  if (!match) return false;
  const [, rawScheme, rawHost, rawPort, rawTransport] = match;
  const scheme = rawScheme.toLowerCase();
  const host = rawHost.toLowerCase();
  const port = Number(rawPort);
  const transport = rawTransport?.toLowerCase();

  if (scheme === 'stun') {
    return host === 'stun.cloudflare.com' && port === 3478 && transport === undefined;
  }
  if (host !== 'turn.cloudflare.com') return false;
  if (scheme === 'turn') {
    return (port === 3478 && (transport === 'udp' || transport === 'tcp'))
      || (port === 80 && transport === 'tcp');
  }
  return scheme === 'turns'
    && (port === 5349 || port === 443)
    && transport === 'tcp';
}
