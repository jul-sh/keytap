/** Signaling, session coordination, and TURN authorization for nearby approval. */
const CORS_ORIGINS = new Set([
  "https://keytap.jul.sh",
]);

const RENDEZVOUS_ID_PATTERN = "[a-zA-Z0-9_-]{43}";
const SIGNAL_ROUTE_PATTERN = new RegExp(
  `^/signal/(${RENDEZVOUS_ID_PATTERN})` +
    "(?:/(turn/challenge|turn/authorize|turn|complete))?$",
);
const TURN_CREDENTIAL_TTL_SECONDS = 1200;
// A credential minted at any point in a room must remain valid through that
// room's deadline because each one-shot room receives only one allocation.
const SIGNAL_SESSION_TTL_MS = TURN_CREDENTIAL_TTL_SECONDS * 1000;
const TURN_PASSKEY_AUTHORIZATION_CONTEXT =
  "keytap:turn-passkey-authorization:v1\0";
const SIGNAL_RENDEZVOUS_CONTEXT = "keytap:rendezvous:v1\0";
const SIGNAL_COMPLETION_CONTEXT = "keytap:signal-completion:v1\0";
// Covers time spent reading the consent UI plus the full two-minute WebAuthn
// prompt without misclassifying a slow but valid approval as unallowlisted.
const TURN_PASSKEY_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const TURN_PASSKEY_PROOF_MAX_BYTES = 8 * 1024;
const SIGNAL_COMPLETION_PROOF_MAX_BYTES = 1024;
const MAX_SIGNAL_BYTES = 128 * 1024;
const MAX_SIGNAL_MESSAGES_PER_SOCKET = 8;
const TURN_PROVIDER_RESPONSE_MAX_BYTES = 64 * 1024;
const SIGNAL_LIFECYCLE_KEY = "signal:lifecycle";
const TURN_CREDENTIAL_CACHE_KEY = "turn:credential";
const TURN_PASSKEY_CHALLENGE_KEY = "turn:passkey-challenge";
const SIGNAL_COMPLETED_ELSEWHERE_MESSAGE =
  '{"type":"completed-elsewhere"}';
const TURN_PASSKEY_ALLOWLIST = Object.freeze([
  Object.freeze({
    credentialId: "YMrfg78V4cqfr7NqwX_PkFZa13Y",
    publicKey: "Fl1qDq-BqriovSqe40CPvq3rz6ltvoSoQM6gSuJfIsA",
  }),
]);

/** @typedef {"cli" | "approver"} SignalRole */

/**
 * @typedef {
 *   | { kind: "socket", rendezvousId: string }
 *   | { kind: "turn-credential", rendezvousId: string }
 *   | { kind: "turn-challenge", rendezvousId: string }
 *   | { kind: "turn-authorization", rendezvousId: string }
 *   | { kind: "completion", rendezvousId: string }
 *   | { kind: "invalid" }
 * } SignalRoute
 */

/**
 * @typedef {
 *   | { kind: "missing" }
 *   | { kind: "configured", keyId: string, apiToken: string }
 * } TurnConfiguration
 */

/**
 * @typedef {
 *   | { kind: "authorized", capabilityHash: string }
 *   | { kind: "pending-passkey" }
 * } TurnEntitlement
 */

/**
 * @typedef {{
 *   credentialId: string,
 *   verificationKey: CryptoKey
 * }} TurnPasskeyIdentity
 */

/**
 * @typedef {
 *   | { kind: "decoded", bytes: Uint8Array }
 *   | { kind: "invalid" }
 * } DecodedBase64Url
 */

/**
 * @typedef {
 *   | { kind: "parsed", challenge: string, challengeBytes: Uint8Array,
 *       expiresAt: number, credentialId: string, credentialIdBytes: Uint8Array,
 *       publicKey: string, publicKeyBytes: Uint8Array, signature: Uint8Array }
 *   | { kind: "invalid" }
 * } ParsedTurnPasskeyProof
 */

/**
 * @typedef {
 *   | { kind: "cli" }
 *   | { kind: "approver" }
 * } SignalAdmission
 */

/**
 * @typedef {
 *   | { kind: "missing" }
 *   | { kind: "invalid" }
 *   | { kind: "active", expiresAt: number, turnEntitlement: TurnEntitlement }
 *   | { kind: "closed", expiresAt: number }
 *   | { kind: "completed-elsewhere", expiresAt: number }
 * } SignalLifecycle
 */

/**
 * @typedef {
 *   | { kind: "active" }
 *   | { kind: "duplicate-cli" }
 *   | { kind: "closed" }
 *   | { kind: "completed-elsewhere" }
 *   | { kind: "expired" }
 * } SignalAdmissionResult
 */

/**
 * @typedef {
 *   | { kind: "not-terminal" }
 *   | { kind: "invalid-terminal" }
 *   | { kind: "completed-elsewhere" }
 * } SignalTerminalControl
 */

/**
 * @typedef {
 *   | { kind: "parsed", publicKey: Uint8Array, signature: Uint8Array }
 *   | { kind: "invalid" }
 * } ParsedSignalCompletionProof
 */

/**
 * @typedef {
 *   | { kind: "authorized" }
 *   | { kind: "denied" }
 *   | { kind: "configuration-error" }
 * } SignalCompletionAuthorization
 */

/**
 * @typedef {
 *   | { kind: "missing" }
 *   | { kind: "invalid" }
 *   | { kind: "issued", challenge: string, expiresAt: number }
 * } TurnPasskeyChallenge
 */

/**
 * @typedef {
 *   | { kind: "missing" }
 *   | { kind: "invalid" }
 *   | { kind: "cached", capabilityHash: string, serialized: string }
 * } TurnCredentialCache
 */

/**
 * @typedef {
 *   | { kind: "missing" }
 *   | { kind: "invalid" }
 *   | { kind: "capability-mismatch" }
 *   | { kind: "ready", serialized: string }
 * } ResolvedTurnCredentialCache
 */

/**
 * @typedef {
 *   | { kind: "idle" }
 *   | { kind: "pending", capabilityHash: string,
 *       promise: Promise<TurnCredentialResult> }
 * } TurnCredentialMint
 */

/**
 * @typedef {
 *   | { kind: "parsed", signature: Uint8Array }
 *   | { kind: "invalid" }
 * } ParsedTurnCapability
 */

/**
 * @typedef {
 *   | { kind: "authorized" }
 *   | { kind: "denied" }
 *   | { kind: "configuration-error" }
 * } TurnCapabilityAuthorization
 */

/**
 * @typedef {
 *   | { kind: "hashed", value: string }
 *   | { kind: "configuration-error" }
 * } TurnCapabilityHash
 */

/**
 * @typedef {
 *   | { kind: "ready", serialized: string }
 *   | { kind: "expired" }
 *   | { kind: "completed-elsewhere" }
 *   | { kind: "pending-passkey" }
 * } TurnCredentialResult
 */

const TURN_PASSKEY_VERIFIERS =
  importTurnPasskeyAllowlist(TURN_PASSKEY_ALLOWLIST);

/**
 * @param {Request} request
 * @returns {HeadersInit}
 */
function corsHeaders(request) {
  const origin = request.headers.get("Origin") || "";
  const allowed = CORS_ORIGINS.has(origin) ? origin : "";
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

/**
 * Parse an untrusted role at the HTTP boundary.
 * @param {string | null} value
 * @returns {SignalRole | null}
 */
function parseSignalRole(value) {
  switch (value) {
    case "cli":
    case "approver":
      return value;
    default:
      return null;
  }
}

/**
 * Parse the complete public route surface and reject non-canonical room IDs.
 * @param {string} pathname
 * @returns {SignalRoute}
 */
function parseSignalRoute(pathname) {
  const match = pathname.match(SIGNAL_ROUTE_PATTERN);
  if (!match) {
    return { kind: "invalid" };
  }
  const rendezvousId = decodeBase64Url(match[1]);
  if (
    rendezvousId.kind !== "decoded" ||
    rendezvousId.bytes.byteLength !== 32
  ) {
    return { kind: "invalid" };
  }

  switch (match[2]) {
    case undefined:
      return { kind: "socket", rendezvousId: match[1] };
    case "turn":
      return { kind: "turn-credential", rendezvousId: match[1] };
    case "turn/challenge":
      return { kind: "turn-challenge", rendezvousId: match[1] };
    case "turn/authorize":
      return { kind: "turn-authorization", rendezvousId: match[1] };
    case "complete":
      return { kind: "completion", rendezvousId: match[1] };
    default:
      return { kind: "invalid" };
  }
}

/**
 * @param {URLSearchParams} searchParams
 * @returns {SignalAdmission | { kind: "invalid" }}
 */
function parseSignalAdmission(searchParams) {
  const entries = [...searchParams.entries()];
  if (entries.length !== 1 || entries[0][0] !== "role") {
    return { kind: "invalid" };
  }
  const role = parseSignalRole(entries[0][1]);
  switch (role) {
    case "cli":
      return { kind: "cli" };
    case "approver":
      return { kind: "approver" };
    case null:
      return { kind: "invalid" };
  }
}

/**
 * Reserve one byte-exact signaling frame for the CLI's terminal transition.
 * A decoded lookalike with whitespace, duplicate keys, or extra fields is
 * rejected instead of being mistaken for either a terminal control or an
 * opaque WebRTC envelope.
 * @param {string} value
 * @returns {SignalTerminalControl}
 */
function parseSignalTerminalControl(value) {
  if (value === SIGNAL_COMPLETED_ELSEWHERE_MESSAGE) {
    return { kind: "completed-elsewhere" };
  }

  try {
    const parsed = JSON.parse(value);
    if (
      parsed &&
      typeof parsed === "object" &&
      !Array.isArray(parsed) &&
      parsed.type === "completed-elsewhere"
    ) {
      return { kind: "invalid-terminal" };
    }
  } catch {
    // Signaling envelopes remain opaque to the relay.
  }
  return { kind: "not-terminal" };
}

/**
 * Parse the private-key proof used to retire a room independently of its
 * WebSocket. The public key must also hash to the rendezvous path before the
 * signature is considered.
 * @param {unknown} value
 * @returns {ParsedSignalCompletionProof}
 */
function parseSignalCompletionProof(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !==
      "from,kind,publicKey,signature,v" ||
    value.v !== 1 ||
    value.from !== "cli" ||
    value.kind !== "completed-elsewhere" ||
    typeof value.publicKey !== "string" ||
    typeof value.signature !== "string"
  ) {
    return { kind: "invalid" };
  }
  const publicKey = decodeBase64Url(value.publicKey);
  const signature = decodeBase64Url(value.signature);
  if (
    publicKey.kind !== "decoded" ||
    publicKey.bytes.byteLength !== 32 ||
    signature.kind !== "decoded" ||
    signature.bytes.byteLength !== 64
  ) {
    return { kind: "invalid" };
  }
  return {
    kind: "parsed",
    publicKey: publicKey.bytes,
    signature: signature.bytes,
  };
}

/**
 * Parse the TURN capability persisted with a signaling room.
 * @param {unknown} value
 * @returns {TurnEntitlement | { kind: "invalid" }}
 */
function parseTurnEntitlement(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || !("kind" in value)) {
    return { kind: "invalid" };
  }
  switch (value.kind) {
    case "pending-passkey":
      return Object.keys(value).length === 1
        ? { kind: "pending-passkey" }
        : { kind: "invalid" };
    case "authorized":
      if (
        Object.keys(value).length === 2 &&
        "capabilityHash" in value &&
        typeof value.capabilityHash === "string"
      ) {
        const capabilityHash = decodeBase64Url(value.capabilityHash);
        if (
          capabilityHash.kind === "decoded" &&
          capabilityHash.bytes.byteLength === 32
        ) {
          return {
            kind: "authorized",
            capabilityHash: value.capabilityHash,
          };
        }
      }
      return { kind: "invalid" };
    default:
      return { kind: "invalid" };
  }
}

/**
 * Invalid stored challenge state is never replaced implicitly: authorization
 * remains unavailable rather than accepting a proof against ambiguous state.
 * @param {unknown} value
 * @returns {TurnPasskeyChallenge}
 */
function parseTurnPasskeyChallenge(value) {
  if (value === undefined) {
    return { kind: "missing" };
  }
  if (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === 3 &&
    value.kind === "issued" &&
    typeof value.challenge === "string" &&
    value.challenge.length === 43 &&
    Number.isSafeInteger(value.expiresAt) &&
    value.expiresAt > 0
  ) {
    const challenge = decodeBase64Url(value.challenge);
    if (challenge.kind === "decoded" && challenge.bytes.byteLength === 32) {
      return {
        kind: "issued",
        challenge: value.challenge,
        expiresAt: value.expiresAt,
      };
    }
  }
  return { kind: "invalid" };
}

/**
 * Parse lifecycle data read from Durable Object storage. Missing and corrupt
 * state are distinct so callers can create only at WebSocket admission while
 * all credential paths fail closed.
 * @param {unknown} value
 * @returns {SignalLifecycle}
 */
function parseSignalLifecycle(value) {
  if (value === undefined) {
    return { kind: "missing" };
  }
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    !("kind" in value) ||
    !("expiresAt" in value) ||
    !Number.isSafeInteger(value.expiresAt) ||
    value.expiresAt <= 0
  ) {
    return { kind: "invalid" };
  }

  switch (value.kind) {
    case "active": {
      if (
        Object.keys(value).length !== 3 ||
        !("turnEntitlement" in value)
      ) {
        return { kind: "invalid" };
      }
      const turnEntitlement = parseTurnEntitlement(value.turnEntitlement);
      if (turnEntitlement.kind === "invalid") {
        return { kind: "invalid" };
      }
      return {
        kind: "active",
        expiresAt: value.expiresAt,
        turnEntitlement,
      };
    }
    case "closed":
      return Object.keys(value).length === 2
        ? { kind: "closed", expiresAt: value.expiresAt }
        : { kind: "invalid" };
    case "completed-elsewhere":
      return Object.keys(value).length === 2
        ? { kind: "completed-elsewhere", expiresAt: value.expiresAt }
        : { kind: "invalid" };
    default:
      return { kind: "invalid" };
  }
}

/**
 * Fail closed when persisted credential data is malformed.
 * @param {unknown} value
 * @returns {TurnCredentialCache}
 */
function parseTurnCredentialCache(value) {
  if (value === undefined) {
    return { kind: "missing" };
  }
  if (
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === 3 &&
    "kind" in value &&
    value.kind === "cached" &&
    "capabilityHash" in value &&
    typeof value.capabilityHash === "string" &&
    "serialized" in value &&
    typeof value.serialized === "string" &&
    new TextEncoder().encode(value.serialized).byteLength <=
      TURN_PROVIDER_RESPONSE_MAX_BYTES
  ) {
    const capabilityHash = decodeBase64Url(value.capabilityHash);
    if (
      capabilityHash.kind === "decoded" &&
      capabilityHash.bytes.byteLength === 32
    ) {
      return {
        kind: "cached",
        capabilityHash: value.capabilityHash,
        serialized: value.serialized,
      };
    }
  }
  return { kind: "invalid" };
}

/**
 * Resolve persisted cache state against the bearer capability authorized for
 * the active room. A mismatch is ambiguous and must fail closed rather than
 * minting a second credential.
 * @param {TurnCredentialCache} cache
 * @param {{ turnEntitlement:
 *   { kind: "authorized", capabilityHash: string } }} lifecycle
 * @returns {ResolvedTurnCredentialCache}
 */
function resolveTurnCredentialCache(cache, lifecycle) {
  switch (cache.kind) {
    case "missing":
      return cache;
    case "invalid":
      return cache;
    case "cached":
      if (cache.capabilityHash !== lifecycle.turnEntitlement.capabilityHash) {
        return { kind: "capability-mismatch" };
      }
      return { kind: "ready", serialized: cache.serialized };
  }
}

/**
 * Strictly decode canonical, unpadded base64url.
 * @param {string} value
 * @returns {DecodedBase64Url}
 */
function decodeBase64Url(value) {
  if (
    value.length === 0 ||
    value.length % 4 === 1 ||
    !/^[A-Za-z0-9_-]+$/.test(value)
  ) {
    return { kind: "invalid" };
  }

  try {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/") +
      "=".repeat((4 - (value.length % 4)) % 4);
    const binary = atob(padded);
    const canonical = btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");
    if (canonical !== value) {
      return { kind: "invalid" };
    }
    return {
      kind: "decoded",
      bytes: Uint8Array.from(binary, (character) => character.charCodeAt(0)),
    };
  } catch {
    return { kind: "invalid" };
  }
}

/** @param {Uint8Array} bytes */
function encodeBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

/**
 * Parse exactly one bearer credential containing the canonical 64-byte proof
 * signature. It is never accepted from a URL or request body.
 * @param {string | null} value
 * @returns {ParsedTurnCapability}
 */
function parseTurnCapability(value) {
  if (typeof value !== "string" || !value.startsWith("Bearer ")) {
    return { kind: "invalid" };
  }
  const signature = decodeBase64Url(value.slice("Bearer ".length));
  if (
    signature.kind !== "decoded" ||
    signature.bytes.byteLength !== 64
  ) {
    return { kind: "invalid" };
  }
  return { kind: "parsed", signature: signature.bytes };
}

/**
 * @param {Uint8Array} left
 * @param {Uint8Array} right
 */
function constantTimeEqual(left, right) {
  if (left.byteLength !== right.byteLength) {
    return false;
  }
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= left[index] ^ right[index];
  }
  return difference === 0;
}

/**
 * Persist only a one-way, canonical digest of the bearer capability.
 * @param {Uint8Array} signature
 * @returns {Promise<TurnCapabilityHash>}
 */
async function hashTurnCapability(signature) {
  try {
    const digest = new Uint8Array(
      await crypto.subtle.digest("SHA-256", signature),
    );
    return { kind: "hashed", value: encodeBase64Url(digest) };
  } catch {
    return { kind: "configuration-error" };
  }
}

/**
 * Compare a supplied bearer capability to the persisted digest without
 * exposing the digest or the proof signature in any response.
 * @param {string | null} authorization
 * @param {string} expectedHash
 * @returns {Promise<TurnCapabilityAuthorization>}
 */
async function authorizeTurnCapability(authorization, expectedHash) {
  const capability = parseTurnCapability(authorization);
  switch (capability.kind) {
    case "invalid":
      return { kind: "denied" };
    case "parsed":
      break;
  }
  const actualHash = await hashTurnCapability(capability.signature);
  switch (actualHash.kind) {
    case "configuration-error":
      return actualHash;
    case "hashed":
      break;
  }
  const expected = decodeBase64Url(expectedHash);
  if (expected.kind !== "decoded" || expected.bytes.byteLength !== 32) {
    return { kind: "configuration-error" };
  }
  const actual = decodeBase64Url(actualHash.value);
  if (actual.kind !== "decoded" || actual.bytes.byteLength !== 32) {
    return { kind: "configuration-error" };
  }
  return constantTimeEqual(actual.bytes, expected.bytes)
    ? { kind: "authorized" }
    : { kind: "denied" };
}

/**
 * Import the checked-in public keys once per Worker isolate.
 * @param {readonly { credentialId: string, publicKey: string }[]} allowlist
 * @returns {Promise<Map<string, TurnPasskeyIdentity>>}
 */
async function importTurnPasskeyAllowlist(allowlist) {
  const entries = await Promise.all(allowlist.map(async (value) => {
    const publicKey = decodeBase64Url(value.publicKey);
    if (
      publicKey.kind === "invalid" ||
      publicKey.bytes.byteLength !== 32
    ) {
      throw new Error("invalid TURN passkey allowlist");
    }

    const verificationKey = await crypto.subtle.importKey(
      "raw",
      publicKey.bytes,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return [value.publicKey, {
      credentialId: value.credentialId,
      verificationKey,
    }];
  }));
  return new Map(entries);
}

/**
 * Strictly parse the only proof shape accepted at the HTTP boundary.
 * @param {unknown} value
 * @returns {ParsedTurnPasskeyProof}
 */
function parseTurnPasskeyProof(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !==
      "challenge,credentialId,expiresAt,kind,publicKey,signature" ||
    value.kind !== "turn-passkey-proof" ||
    typeof value.challenge !== "string" ||
    typeof value.credentialId !== "string" ||
    typeof value.publicKey !== "string" ||
    typeof value.signature !== "string" ||
    !Number.isSafeInteger(value.expiresAt) ||
    value.expiresAt <= 0
  ) {
    return { kind: "invalid" };
  }

  const challenge = decodeBase64Url(value.challenge);
  const credentialId = decodeBase64Url(value.credentialId);
  const publicKey = decodeBase64Url(value.publicKey);
  const signature = decodeBase64Url(value.signature);
  if (
    challenge.kind === "invalid" ||
    challenge.bytes.byteLength !== 32 ||
    credentialId.kind === "invalid" ||
    credentialId.bytes.byteLength < 1 ||
    credentialId.bytes.byteLength > 1024 ||
    publicKey.kind === "invalid" ||
    publicKey.bytes.byteLength !== 32 ||
    signature.kind === "invalid" ||
    signature.bytes.byteLength !== 64
  ) {
    return { kind: "invalid" };
  }

  return {
    kind: "parsed",
    challenge: value.challenge,
    challengeBytes: challenge.bytes,
    expiresAt: value.expiresAt,
    credentialId: value.credentialId,
    credentialIdBytes: credentialId.bytes,
    publicKey: value.publicKey,
    publicKeyBytes: publicKey.bytes,
    signature: signature.bytes,
  };
}

/** @param {number} value */
function u32(value) {
  const encoded = new Uint8Array(4);
  new DataView(encoded.buffer).setUint32(0, value, false);
  return encoded;
}

/** @param {number} value */
function u64(value) {
  const encoded = new Uint8Array(8);
  new DataView(encoded.buffer).setBigUint64(0, BigInt(value), false);
  return encoded;
}

/** @param {Uint8Array} value */
function lengthPrefixed(value) {
  const encoded = new Uint8Array(4 + value.byteLength);
  encoded.set(u32(value.byteLength), 0);
  encoded.set(value, 4);
  return encoded;
}

/** @param {...Uint8Array} values */
function concatenate(...values) {
  const encoded = new Uint8Array(
    values.reduce((length, value) => length + value.byteLength, 0),
  );
  let offset = 0;
  for (const value of values) {
    encoded.set(value, offset);
    offset += value.byteLength;
  }
  return encoded;
}

/** @param {string} rendezvousId */
function signalCompletionMessage(rendezvousId) {
  const encoder = new TextEncoder();
  return concatenate(
    encoder.encode(SIGNAL_COMPLETION_CONTEXT),
    lengthPrefixed(encoder.encode(rendezvousId)),
  );
}

/**
 * Require both possession of the invitation private key and an exact match between
 * its public key and the hash-derived room path.
 * @param {string} rendezvousId
 * @param {{ publicKey: Uint8Array, signature: Uint8Array }} proof
 * @returns {Promise<SignalCompletionAuthorization>}
 */
async function authorizeSignalCompletion(rendezvousId, proof) {
  try {
    const encoder = new TextEncoder();
    const expectedRendezvous = decodeBase64Url(rendezvousId);
    if (
      expectedRendezvous.kind !== "decoded" ||
      expectedRendezvous.bytes.byteLength !== 32
    ) {
      return { kind: "denied" };
    }
    const actualRendezvous = new Uint8Array(await crypto.subtle.digest(
      "SHA-256",
      concatenate(encoder.encode(SIGNAL_RENDEZVOUS_CONTEXT), proof.publicKey),
    ));
    if (!constantTimeEqual(actualRendezvous, expectedRendezvous.bytes)) {
      return { kind: "denied" };
    }
    const verificationKey = await crypto.subtle.importKey(
      "raw",
      proof.publicKey,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      { name: "Ed25519" },
      verificationKey,
      proof.signature,
      signalCompletionMessage(rendezvousId),
    )
      ? { kind: "authorized" }
      : { kind: "denied" };
  } catch {
    return { kind: "configuration-error" };
  }
}

/**
 * Canonical room authorization signed by the passkey-derived Ed25519
 * identity. Every variable-width field is u32-BE length-prefixed; expiry is
 * epoch milliseconds encoded as u64-BE.
 * @param {string} rendezvousId
 * @param {{ challengeBytes: Uint8Array, expiresAt: number,
 *   credentialIdBytes: Uint8Array, publicKeyBytes: Uint8Array }} proof
 */
function turnPasskeyAuthorizationMessage(rendezvousId, proof) {
  const encoder = new TextEncoder();
  return concatenate(
    encoder.encode(TURN_PASSKEY_AUTHORIZATION_CONTEXT),
    lengthPrefixed(encoder.encode(rendezvousId)),
    lengthPrefixed(proof.challengeBytes),
    u64(proof.expiresAt),
    lengthPrefixed(proof.credentialIdBytes),
    lengthPrefixed(proof.publicKeyBytes),
  );
}

/**
 * @param {unknown} env
 * @returns {TurnConfiguration}
 */
function turnConfiguration(env) {
  if (
    env &&
    typeof env === "object" &&
    "TURN_KEY_ID" in env &&
    "TURN_KEY_API_TOKEN" in env &&
    typeof env.TURN_KEY_ID === "string" &&
    env.TURN_KEY_ID.length > 0 &&
    typeof env.TURN_KEY_API_TOKEN === "string" &&
    env.TURN_KEY_API_TOKEN.length > 0
  ) {
    return {
      kind: "configured",
      keyId: env.TURN_KEY_ID,
      apiToken: env.TURN_KEY_API_TOKEN,
    };
  }
  return { kind: "missing" };
}

/**
 * Read an untrusted request body without allowing an absent Content-Length to
 * bypass the limit.
 * @param {Request} request
 * @param {number} maximumBytes
 * @returns {Promise<{kind: "read", bytes: Uint8Array} | {kind: "invalid"}>}
 */
async function readBoundedRequestBody(request, maximumBytes) {
  const declared = request.headers.get("Content-Length");
  if (declared !== null) {
    if (!/^(?:0|[1-9][0-9]*)$/.test(declared) || Number(declared) > maximumBytes) {
      return { kind: "invalid" };
    }
  }
  if (request.body === null) {
    return { kind: "read", bytes: new Uint8Array() };
  }

  const reader = request.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximumBytes) {
        await reader.cancel();
        return { kind: "invalid" };
      }
      chunks.push(value);
    }
  } catch {
    return { kind: "invalid" };
  }

  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { kind: "read", bytes };
}

/**
 * @param {Request} request
 * @returns {Promise<unknown | undefined>}
 */
async function readTurnPasskeyProofBody(request) {
  const body = await readBoundedRequestBody(request, TURN_PASSKEY_PROOF_MAX_BYTES);
  if (body.kind === "invalid" || body.bytes.byteLength === 0) {
    return undefined;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body.bytes));
  } catch {
    return undefined;
  }
}

/** @param {Request} request */
async function readSignalCompletionProofBody(request) {
  const body = await readBoundedRequestBody(
    request,
    SIGNAL_COMPLETION_PROOF_MAX_BYTES,
  );
  if (body.kind === "invalid" || body.bytes.byteLength === 0) {
    return undefined;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body.bytes));
  } catch {
    return undefined;
  }
}

/**
 * @param {Request} request
 * @param {number} status
 * @param {string} message
 * @param {HeadersInit} [extraHeaders]
 * @returns {Response}
 */
function errorResponse(request, status, message, extraHeaders = {}) {
  return new Response(message, {
    status,
    headers: {
      ...corsHeaders(request),
      ...extraHeaders,
      "Cache-Control": "no-store",
    },
  });
}

/**
 * Stable machine-readable TURN policy failures for client error handling.
 * @param {Request} request
 * @param {401 | 403 | 409 | 503} status
 * @param {"turn-capability-invalid" | "turn-not-allowlisted" |
 *   "turn-challenge-expired" | "turn-configuration-error"} kind
 * @returns {Response}
 */
function turnPolicyError(request, status, kind) {
  return new Response(JSON.stringify({ kind }), {
    status,
    headers: {
      ...corsHeaders(request),
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });
}

/**
 * @param {Request} request
 * @param {object} value
 * @returns {Response}
 */
function turnJsonResponse(request, value) {
  return new Response(JSON.stringify(value), {
    status: 200,
    headers: {
      ...corsHeaders(request),
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
    },
  });
}

export default {
  /**
   * @param {Request} request
   * @param {{ SIGNAL_SESSION: DurableObjectNamespace }} env
   * @returns {Promise<Response>}
   */
  async fetch(request, env) {
    const url = new URL(request.url);
    const route = parseSignalRoute(url.pathname);
    if (route.kind === "invalid") {
      return new Response("Not found", { status: 404 });
    }

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    const id = env.SIGNAL_SESSION.idFromName(route.rendezvousId);
    const stub = env.SIGNAL_SESSION.get(id);
    return stub.fetch(request);
  },
};

/**
 * A short-lived, single-use WebRTC signaling room. SDP is forwarded as an
 * opaque, bounded string: authentication belongs to the invitation-key-derived
 * protocol at the endpoints, not to this relay.
 */
export class SignalSession {
  /**
   * @param {DurableObjectState} state
   * @param {unknown} env
   */
  constructor(state, env) {
    this.state = state;
    this.env = env;
    /** @type {TurnCredentialMint} */
    this.turnCredentialMint = { kind: "idle" };
  }

  /**
   * @param {Request} request
   * @returns {Promise<Response>}
   */
  async fetch(request) {
    const url = new URL(request.url);
    const route = parseSignalRoute(url.pathname);
    if (route.kind === "invalid") {
      return errorResponse(request, 404, "Not found");
    }
    if (route.kind !== "socket" && url.search !== "") {
      return errorResponse(request, 400, "Query parameters are not allowed");
    }

    switch (route.kind) {
      case "turn-credential":
        if (request.method !== "GET") {
          return errorResponse(request, 405, "Method not allowed", { Allow: "GET" });
        }
        return this.fetchTurnCredential(request);
      case "turn-challenge":
        if (request.method !== "POST") {
          return errorResponse(request, 405, "Method not allowed", { Allow: "POST" });
        }
        return this.issueTurnPasskeyChallenge(request, route.rendezvousId);
      case "turn-authorization":
        if (request.method !== "POST") {
          return errorResponse(request, 405, "Method not allowed", { Allow: "POST" });
        }
        return this.authorizeTurnWithPasskey(request, route.rendezvousId);
      case "completion":
        if (request.method !== "POST") {
          return errorResponse(request, 405, "Method not allowed", { Allow: "POST" });
        }
        return this.completeWithCliProof(request, route.rendezvousId);
      case "socket":
        break;
      case "invalid":
        return errorResponse(request, 404, "Not found");
    }

    if (request.method !== "GET" || request.headers.get("Upgrade") !== "websocket") {
      return errorResponse(request, 426, "WebSocket upgrade required", {
        Upgrade: "websocket",
      });
    }

    const admission = parseSignalAdmission(url.searchParams);
    switch (admission.kind) {
      case "invalid":
        return errorResponse(
          request,
          400,
          "query must contain exactly one role=cli or role=approver",
        );
      case "cli":
      case "approver":
        break;
    }
    const role = admission.kind;

    const admissionResult = await this.beginOrJoinSignalSession(admission);
    switch (admissionResult.kind) {
      case "expired":
      case "closed":
        return errorResponse(request, 410, "Signal session expired");
      case "duplicate-cli":
        return errorResponse(request, 409, "cli is already connected");
      case "completed-elsewhere":
        return role === "approver"
          ? this.completedElsewhereUpgrade()
          : errorResponse(request, 410, "Signal session completed elsewhere");
      case "active":
        break;
    }

    if (
      role === "approver" &&
      this.socketsForRole("cli").length !== 1
    ) {
      return errorResponse(request, 410, "CLI is no longer waiting");
    }

    if (this.socketsForRole(role).length !== 0) {
      return errorResponse(request, 409, `${role} is already connected`);
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.serializeAttachment({
      kind: "peer",
      role,
      forwardedMessages: 0,
    });
    this.state.acceptWebSocket(server, [role]);
    this.notifyPeerReady();

    return new Response(null, { status: 101, webSocket: client });
  }

  /**
   * Let an approver opening a terminal invitation receive the same typed outcome
   * as an approver that was connected when the native approval won. The terminal
   * attachment deliberately cannot retire or mutate the persisted tombstone
   * when its replay-only socket closes.
   * @returns {Response}
   */
  completedElsewhereUpgrade() {
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.serializeAttachment({
      kind: "terminal",
      outcome: "completed-elsewhere",
    });
    this.state.acceptWebSocket(server);
    try { server.send(SIGNAL_COMPLETED_ELSEWHERE_MESSAGE); } catch {}
    try { server.close(1000, "session completed elsewhere"); } catch {}
    return new Response(null, { status: 101, webSocket: client });
  }

  /**
   * @param {SignalRole} role
   * @returns {WebSocket[]}
   */
  socketsForRole(role) {
    return this.state.getWebSockets(role).filter((socket) => {
      const attachment = socket.deserializeAttachment();
      return (
        attachment &&
        attachment.kind === "peer" &&
        attachment.role === role &&
        socket.readyState === WebSocket.OPEN
      );
    });
  }

  notifyPeerReady() {
    const cli = this.socketsForRole("cli");
    const approver = this.socketsForRole("approver");
    if (cli.length === 1 && approver.length === 1) {
      const message = JSON.stringify({ type: "peer-ready" });
      try { cli[0].send(message); } catch {}
      try { approver[0].send(message); } catch {}
    }
  }

  /**
   * Issue one cached nonce only after both signaling peers
   * are live. Bad proofs do not rotate it, so an invitation observer cannot
   * invalidate the owner's in-flight passkey prompt merely by submitting junk.
   * @param {Request} request
   * @param {string} rendezvousId
   * @returns {Promise<Response>}
   */
  async issueTurnPasskeyChallenge(request, rendezvousId) {
    const body = await readBoundedRequestBody(request, 0);
    if (body.kind === "invalid" || body.bytes.byteLength !== 0) {
      return errorResponse(request, 400, "Challenge request body must be empty");
    }

    const lifecycle = await this.requireActiveSignalSession();
    switch (lifecycle.kind) {
      case "expired":
        return errorResponse(request, 410, "Signal session expired");
      case "completed-elsewhere":
        return errorResponse(request, 410, "Signal session completed elsewhere");
      case "active":
        break;
    }
    if (
      this.socketsForRole("cli").length !== 1 ||
      this.socketsForRole("approver").length !== 1
    ) {
      return errorResponse(request, 409, "Both signaling peers must be connected");
    }

    const provider = turnConfiguration(this.env);
    if (provider.kind !== "configured") {
      return turnPolicyError(request, 503, "turn-configuration-error");
    }

    const candidateBytes = new Uint8Array(32);
    crypto.getRandomValues(candidateBytes);
    const candidateChallenge = encodeBase64Url(candidateBytes);
    const challengeResult = await this.state.storage.transaction(async (transaction) => {
      const current = parseSignalLifecycle(
        await transaction.get(SIGNAL_LIFECYCLE_KEY),
      );
      switch (current.kind) {
        case "completed-elsewhere":
          return { kind: "completed-elsewhere" };
        case "closed":
        case "missing":
        case "invalid":
          return { kind: "expired" };
        case "active":
          if (
            current.expiresAt !== lifecycle.expiresAt ||
            current.expiresAt <= Date.now()
          ) {
            return { kind: "expired" };
          }
          break;
      }

      const stored = parseTurnPasskeyChallenge(
        await transaction.get(TURN_PASSKEY_CHALLENGE_KEY),
      );
      switch (stored.kind) {
        case "invalid":
          return { kind: "configuration-error" };
        case "issued":
          if (stored.expiresAt > Date.now()) {
            return { kind: "ready", challenge: stored };
          }
          break;
        case "missing":
          break;
      }

      const challenge = {
        kind: "issued",
        challenge: candidateChallenge,
        expiresAt: Math.min(
          Date.now() + TURN_PASSKEY_CHALLENGE_TTL_MS,
          current.expiresAt,
        ),
      };
      await transaction.put(TURN_PASSKEY_CHALLENGE_KEY, challenge);
      return { kind: "ready", challenge };
    });
    switch (challengeResult.kind) {
      case "expired":
        return errorResponse(request, 410, "Signal session expired");
      case "completed-elsewhere":
        return errorResponse(request, 410, "Signal session completed elsewhere");
      case "configuration-error":
        return turnPolicyError(request, 503, "turn-configuration-error");
      case "ready":
        break;
    }
    const issued = challengeResult.challenge;
    return turnJsonResponse(request, {
      kind: "turn-passkey-challenge",
      challenge: issued.challenge,
      expiresAt: issued.expiresAt,
    });
  }

  /**
   * Verify a passkey-derived Ed25519 proof for the room that issued its
   * challenge. Signaling stays public regardless
   * of the result. Identity and signature denials deliberately share one
   * policy response, while stale challenges stay distinct so a slow WebAuthn
   * approval is never misreported as an allowlist denial.
   * @param {Request} request
   * @param {string} rendezvousId
   * @returns {Promise<Response>}
   */
  async authorizeTurnWithPasskey(request, rendezvousId) {
    const lifecycle = await this.requireActiveSignalSession();
    switch (lifecycle.kind) {
      case "expired":
        return errorResponse(request, 410, "Signal session expired");
      case "completed-elsewhere":
        return errorResponse(request, 410, "Signal session completed elsewhere");
      case "active":
        break;
    }
    if (
      this.socketsForRole("cli").length !== 1 ||
      this.socketsForRole("approver").length !== 1
    ) {
      return errorResponse(request, 409, "Both signaling peers must be connected");
    }

    const provider = turnConfiguration(this.env);
    if (provider.kind !== "configured") {
      return turnPolicyError(request, 503, "turn-configuration-error");
    }
    let identities;
    try {
      identities = await TURN_PASSKEY_VERIFIERS;
    } catch {
      return turnPolicyError(request, 503, "turn-configuration-error");
    }

    const proof = parseTurnPasskeyProof(await readTurnPasskeyProofBody(request));
    if (proof.kind === "invalid") {
      return turnPolicyError(request, 403, "turn-not-allowlisted");
    }
    if (proof.expiresAt <= Date.now()) {
      return turnPolicyError(request, 409, "turn-challenge-expired");
    }
    const challenge = parseTurnPasskeyChallenge(
      await this.state.storage.get(TURN_PASSKEY_CHALLENGE_KEY),
    );
    switch (challenge.kind) {
      case "missing":
        return turnPolicyError(request, 409, "turn-challenge-expired");
      case "invalid":
        return turnPolicyError(request, 503, "turn-configuration-error");
      case "issued":
        if (
          challenge.expiresAt <= Date.now() ||
          challenge.challenge !== proof.challenge ||
          challenge.expiresAt !== proof.expiresAt
        ) {
          return turnPolicyError(request, 409, "turn-challenge-expired");
        }
        break;
    }

    const identity = identities.get(proof.publicKey);
    if (
      identity === undefined ||
      identity.credentialId !== proof.credentialId
    ) {
      return turnPolicyError(request, 403, "turn-not-allowlisted");
    }

    let verified;
    try {
      verified = await crypto.subtle.verify(
        { name: "Ed25519" },
        identity.verificationKey,
        proof.signature,
        turnPasskeyAuthorizationMessage(rendezvousId, proof),
      );
    } catch {
      return turnPolicyError(request, 503, "turn-configuration-error");
    }
    if (!verified) {
      return turnPolicyError(request, 403, "turn-not-allowlisted");
    }
    const capabilityHash = await hashTurnCapability(proof.signature);
    switch (capabilityHash.kind) {
      case "configuration-error":
        return turnPolicyError(request, 503, "turn-configuration-error");
      case "hashed":
        break;
    }

    // WebCrypto yields to the event loop. Atomically re-read every mutable
    // binding before publishing authorization so stale or concurrent proofs
    // cannot overwrite one another.
    const transition = await this.state.storage.transaction(async (transaction) => {
      const current = parseSignalLifecycle(
        await transaction.get(SIGNAL_LIFECYCLE_KEY),
      );
      const currentChallenge = parseTurnPasskeyChallenge(
        await transaction.get(TURN_PASSKEY_CHALLENGE_KEY),
      );
      const now = Date.now();
      switch (current.kind) {
        case "missing":
          return { kind: "session-expired" };
        case "invalid":
          return { kind: "configuration-error" };
        case "closed":
          return { kind: "session-expired" };
        case "completed-elsewhere":
          return { kind: "completed-elsewhere" };
        case "active":
          if (current.expiresAt <= now) {
            return { kind: "session-expired" };
          }
          if (current.expiresAt !== lifecycle.expiresAt) {
            return { kind: "challenge-expired" };
          }
          break;
      }
      if (proof.expiresAt <= now) {
        return { kind: "challenge-expired" };
      }
      switch (currentChallenge.kind) {
        case "missing":
          return { kind: "challenge-expired" };
        case "invalid":
          return { kind: "configuration-error" };
        case "issued":
          if (
            currentChallenge.expiresAt <= now ||
            currentChallenge.challenge !== proof.challenge ||
            currentChallenge.expiresAt !== proof.expiresAt
          ) {
            return { kind: "challenge-expired" };
          }
          break;
      }
      if (
        this.socketsForRole("cli").length !== 1 ||
        this.socketsForRole("approver").length !== 1
      ) {
        return { kind: "peers-missing" };
      }
      switch (current.turnEntitlement.kind) {
        case "pending-passkey":
          await transaction.put(SIGNAL_LIFECYCLE_KEY, {
            ...current,
            turnEntitlement: {
              kind: "authorized",
              capabilityHash: capabilityHash.value,
            },
          });
          return { kind: "authorized" };
        case "authorized":
          return current.turnEntitlement.capabilityHash === capabilityHash.value
            ? { kind: "authorized" }
            : { kind: "rejected" };
      }
    });
    switch (transition.kind) {
      case "session-expired":
        await this.closeActiveSignalSession();
        return errorResponse(request, 410, "Signal session expired");
      case "completed-elsewhere":
        return errorResponse(request, 410, "Signal session completed elsewhere");
      case "challenge-expired":
        return turnPolicyError(request, 409, "turn-challenge-expired");
      case "peers-missing":
        return errorResponse(request, 409, "Both signaling peers must be connected");
      case "configuration-error":
        return turnPolicyError(request, 503, "turn-configuration-error");
      case "rejected":
        return turnPolicyError(request, 403, "turn-not-allowlisted");
      case "authorized":
        break;
    }
    return turnJsonResponse(request, { kind: "turn-authorized" });
  }

  /**
   * Only the first CLI admission creates this one-shot room. An approver can
   * join it, but neither role can revive it after the CLI has left. TURN
   * requests never create rooms.
   * @param {SignalAdmission} admission
   * @returns {Promise<SignalAdmissionResult>}
   */
  async beginOrJoinSignalSession(admission) {
    const result = await this.state.storage.transaction(async (transaction) => {
      const current = parseSignalLifecycle(
        await transaction.get(SIGNAL_LIFECYCLE_KEY),
      );
      switch (current.kind) {
        case "invalid":
          return { kind: "invalid" };
        case "closed":
          return current.expiresAt > Date.now()
            ? { kind: "closed", lifecycle: current }
            : { kind: "expired" };
        case "completed-elsewhere":
          return current.expiresAt > Date.now()
            ? { kind: "completed-elsewhere", lifecycle: current }
            : { kind: "expired" };
        case "active":
          if (current.expiresAt <= Date.now()) {
            return { kind: "expired" };
          }
          return admission.kind === "cli"
            ? { kind: "duplicate-cli", lifecycle: current }
            : { kind: "active", lifecycle: current };
        case "missing": {
          if (admission.kind === "approver") {
            return { kind: "expired" };
          }
          const active = {
            kind: "active",
            expiresAt: Date.now() + SIGNAL_SESSION_TTL_MS,
            turnEntitlement: { kind: "pending-passkey" },
          };
          await transaction.put(SIGNAL_LIFECYCLE_KEY, active);
          return { kind: "active", lifecycle: active };
        }
      }
    });
    switch (result.kind) {
      case "active":
      case "duplicate-cli":
      case "closed":
      case "completed-elsewhere":
        await this.ensureLifecycleAlarm(result.lifecycle.expiresAt);
        return { kind: result.kind };
      case "invalid":
        await this.expireSignalSession();
        return { kind: "expired" };
      case "expired":
        await this.expireSignalSession();
        return result;
    }
  }

  /**
   * @returns {Promise<
   *   | { kind: "active", expiresAt: number, turnEntitlement: TurnEntitlement }
   *   | { kind: "completed-elsewhere", expiresAt: number }
   *   | { kind: "expired" }
   * >}
   */
  async requireActiveSignalSession() {
    const lifecycle = parseSignalLifecycle(
      await this.state.storage.get(SIGNAL_LIFECYCLE_KEY),
    );
    switch (lifecycle.kind) {
      case "active":
        if (lifecycle.expiresAt <= Date.now()) {
          await this.expireSignalSession();
          return { kind: "expired" };
        }
        return lifecycle;
      case "closed":
        if (lifecycle.expiresAt <= Date.now()) {
          await this.expireSignalSession();
        }
        return { kind: "expired" };
      case "completed-elsewhere":
        if (lifecycle.expiresAt <= Date.now()) {
          await this.expireSignalSession();
          return { kind: "expired" };
        }
        return lifecycle;
      case "missing":
        return { kind: "expired" };
      case "invalid":
        await this.expireSignalSession();
        return { kind: "expired" };
    }
  }

  /** @param {number} expiresAt */
  async ensureLifecycleAlarm(expiresAt) {
    const alarm = await this.state.storage.getAlarm();
    if (alarm !== expiresAt) {
      await this.state.storage.setAlarm(expiresAt);
    }
  }

  /**
   * @param {Request} request
   * @returns {Promise<Response>}
   */
  async fetchTurnCredential(request) {
    const lifecycle = await this.requireActiveSignalSession();
    switch (lifecycle.kind) {
      case "expired":
        return errorResponse(request, 410, "Signal session expired");
      case "completed-elsewhere":
        return errorResponse(request, 410, "Signal session completed elsewhere");
      case "active":
        break;
    }

    switch (lifecycle.turnEntitlement.kind) {
      case "pending-passkey":
        return turnPolicyError(request, 401, "turn-capability-invalid");
      case "authorized":
        break;
    }

    const capability = await authorizeTurnCapability(
      request.headers.get("Authorization"),
      lifecycle.turnEntitlement.capabilityHash,
    );
    switch (capability.kind) {
      case "denied":
        return turnPolicyError(request, 401, "turn-capability-invalid");
      case "configuration-error":
        return turnPolicyError(request, 503, "turn-configuration-error");
      case "authorized":
        break;
    }

    const config = turnConfiguration(this.env);
    switch (config.kind) {
      case "missing":
        return turnPolicyError(request, 503, "turn-configuration-error");
      case "configured":
        break;
    }

    const cached = resolveTurnCredentialCache(
      parseTurnCredentialCache(
        await this.state.storage.get(TURN_CREDENTIAL_CACHE_KEY),
      ),
      lifecycle,
    );
    switch (cached.kind) {
      case "ready":
        return this.turnCredentialResponse(request, cached.serialized);
      case "invalid":
      case "capability-mismatch":
        return turnPolicyError(request, 503, "turn-configuration-error");
      case "missing":
        break;
    }

    try {
      const result = await this.turnCredentialForRoom(config, lifecycle);
      switch (result.kind) {
        case "expired":
          return errorResponse(request, 410, "Signal session expired");
        case "completed-elsewhere":
          return errorResponse(request, 410, "Signal session completed elsewhere");
        case "pending-passkey":
          return turnPolicyError(request, 401, "turn-capability-invalid");
        case "ready":
          return this.turnCredentialResponse(request, result.serialized);
      }
    } catch {
      return errorResponse(request, 502, "TURN credential provider failed");
    }
  }

  /**
   * Coalesce the full provider, lifecycle-recheck, and cache-write transaction
   * so there is no interval in which another reader can start an allocation.
   * Only the mint promise clears itself; terminal cleanup must not split it.
   * @param {{ kind: "configured", keyId: string, apiToken: string }} config
   * @param {{ kind: "active", expiresAt: number,
   *   turnEntitlement: { kind: "authorized", capabilityHash: string } }} lifecycle
   * @returns {Promise<TurnCredentialResult>}
   */
  async turnCredentialForRoom(config, lifecycle) {
    switch (this.turnCredentialMint.kind) {
      case "pending":
        if (
          this.turnCredentialMint.capabilityHash ===
            lifecycle.turnEntitlement.capabilityHash
        ) {
          return this.turnCredentialMint.promise;
        }
        break;
      case "idle":
        break;
    }

    const promise = this.mintAndCacheTurnCredential(config, lifecycle);
    this.turnCredentialMint = {
      kind: "pending",
      capabilityHash: lifecycle.turnEntitlement.capabilityHash,
      promise,
    };
    try {
      return await promise;
    } finally {
      if (
        this.turnCredentialMint.kind === "pending" &&
        this.turnCredentialMint.promise === promise
      ) {
        this.turnCredentialMint = { kind: "idle" };
      }
    }
  }

  /**
   * @param {{ kind: "configured", keyId: string, apiToken: string }} config
   * @param {{ kind: "active", expiresAt: number,
   *   turnEntitlement: { kind: "authorized", capabilityHash: string } }} lifecycle
   * @returns {Promise<TurnCredentialResult>}
   */
  async mintAndCacheTurnCredential(config, lifecycle) {
    const current = await this.requireActiveSignalSession();
    switch (current.kind) {
      case "expired":
      case "completed-elsewhere":
        return current;
      case "active":
        if (current.expiresAt !== lifecycle.expiresAt) {
          return { kind: "expired" };
        }
        switch (current.turnEntitlement.kind) {
          case "pending-passkey":
            return current.turnEntitlement;
          case "authorized":
            if (
              current.turnEntitlement.capabilityHash !==
                lifecycle.turnEntitlement.capabilityHash
            ) {
              return { kind: "expired" };
            }
            break;
        }
        break;
    }

    const serialized = await this.mintTurnCredential(config);
    const result = await this.state.storage.transaction(async (transaction) => {
      const current = parseSignalLifecycle(
        await transaction.get(SIGNAL_LIFECYCLE_KEY),
      );
      switch (current.kind) {
        case "missing":
        case "invalid":
        case "closed":
          return { kind: "expired" };
        case "completed-elsewhere":
          return current;
        case "active":
          if (
            current.expiresAt <= Date.now() ||
            current.expiresAt !== lifecycle.expiresAt
          ) {
            return { kind: "expired" };
          }
          switch (current.turnEntitlement.kind) {
            case "pending-passkey":
              return current.turnEntitlement;
            case "authorized":
              if (
                current.turnEntitlement.capabilityHash !==
                  lifecycle.turnEntitlement.capabilityHash
              ) {
                return { kind: "expired" };
              }
              break;
          }
          break;
      }
      await transaction.put(TURN_CREDENTIAL_CACHE_KEY, {
        kind: "cached",
        capabilityHash: lifecycle.turnEntitlement.capabilityHash,
        serialized,
      });
      return { kind: "ready", serialized };
    });
    return result;
  }

  /**
   * @param {{ kind: "configured", keyId: string, apiToken: string }} config
   * @returns {Promise<string>}
   */
  async mintTurnCredential(config) {
    const endpoint =
      `https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(config.keyId)}` +
      "/credentials/generate-ice-servers";
    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${config.apiToken}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ ttl: TURN_CREDENTIAL_TTL_SECONDS }),
    });

    if (!response.ok) {
      throw new Error(`TURN provider returned ${response.status}`);
    }

    const body = await response.text();
    if (new TextEncoder().encode(body).byteLength > TURN_PROVIDER_RESPONSE_MAX_BYTES) {
      throw new Error("TURN provider response is too large");
    }

    return body;
  }

  /**
   * @param {Request} request
   * @param {string} serialized
   * @returns {Response}
   */
  turnCredentialResponse(request, serialized) {
    return new Response(serialized, {
      status: 200,
      headers: {
        ...corsHeaders(request),
        "Content-Type": "application/json",
        "Cache-Control": "no-store, private",
      },
    });
  }

  /**
   * Retire a room using a proof signed by the private half of the public key in
   * the invitation fragment. It remains valid even if native approval finishes
   * before the signaling socket connects.
   * @param {Request} request
   * @param {string} rendezvousId
   */
  async completeWithCliProof(request, rendezvousId) {
    const proof = parseSignalCompletionProof(
      await readSignalCompletionProofBody(request),
    );
    if (proof.kind === "invalid") {
      return errorResponse(request, 400, "Invalid completion proof");
    }
    const authorization = await authorizeSignalCompletion(rendezvousId, proof);
    switch (authorization.kind) {
      case "denied":
        return errorResponse(request, 403, "Invalid completion proof");
      case "configuration-error":
        return errorResponse(request, 503, "Completion verification unavailable");
      case "authorized":
        break;
    }

    const transition = await this.completeSignalSessionElsewhere();
    switch (transition.kind) {
      case "published":
      case "already-published":
        return turnJsonResponse(request, { kind: "completed-elsewhere" });
      case "expired":
        return errorResponse(request, 410, "Signal session expired");
      case "invalid":
        await this.expireSignalSession();
        return errorResponse(request, 410, "Signal session expired");
    }
  }

  /**
   * A signed room-key proof can publish completion before the first socket.
   * Storage transactions make that tombstone win over a concurrent admission.
   * @returns {Promise<
   *   | { kind: "published", lifecycle: { kind: "completed-elsewhere", expiresAt: number } }
   *   | { kind: "already-published", lifecycle: { kind: "completed-elsewhere", expiresAt: number } }
   *   | { kind: "expired" }
   *   | { kind: "invalid" }
   * >}
   */
  async completeSignalSessionElsewhere() {
    const transition = await this.state.storage.transaction(async (transaction) => {
      const current = parseSignalLifecycle(
        await transaction.get(SIGNAL_LIFECYCLE_KEY),
      );
      switch (current.kind) {
        case "invalid":
          return { kind: "invalid" };
        case "completed-elsewhere":
          return current.expiresAt > Date.now()
            ? { kind: "already-published", lifecycle: current }
            : { kind: "expired" };
        case "active":
        case "closed": {
          if (current.expiresAt <= Date.now()) {
            return { kind: "expired" };
          }
          const terminal = {
            kind: "completed-elsewhere",
            expiresAt: current.expiresAt,
          };
          await transaction.put(SIGNAL_LIFECYCLE_KEY, terminal);
          await transaction.delete(TURN_PASSKEY_CHALLENGE_KEY);
          await transaction.delete(TURN_CREDENTIAL_CACHE_KEY);
          return { kind: "published", lifecycle: terminal };
        }
        case "missing": {
          const terminal = {
            kind: "completed-elsewhere",
            expiresAt: Date.now() + SIGNAL_SESSION_TTL_MS,
          };
          await transaction.put(SIGNAL_LIFECYCLE_KEY, terminal);
          await transaction.delete(TURN_PASSKEY_CHALLENGE_KEY);
          await transaction.delete(TURN_CREDENTIAL_CACHE_KEY);
          return { kind: "published", lifecycle: terminal };
        }
      }
    });
    switch (transition.kind) {
      case "published":
      case "already-published":
        // The transaction has already made the terminal outcome durable.
        // Notify first so alarm maintenance cannot delay or suppress delivery;
        // still propagate alarm failures so the caller retries maintenance.
        this.notifyCompletedElsewhere();
        await this.ensureLifecycleAlarm(transition.lifecycle.expiresAt);
        return transition;
      case "expired":
      case "invalid":
        return transition;
    }
  }

  notifyCompletedElsewhere() {
    for (const approver of this.socketsForRole("approver")) {
      try { approver.send(SIGNAL_COMPLETED_ELSEWHERE_MESSAGE); } catch {}
    }
    for (const socket of this.state.getWebSockets()) {
      const attachment = socket.deserializeAttachment();
      if (attachment?.kind === "peer") {
        try { socket.close(1000, "session completed elsewhere"); } catch {}
      }
    }
  }

  /**
   * @param {WebSocket} ws
   * @param {string | ArrayBuffer} message
   */
  async webSocketMessage(ws, message) {
    if (typeof message !== "string") {
      try { ws.close(1003, "text messages only"); } catch {}
      return;
    }
    if (new TextEncoder().encode(message).byteLength > MAX_SIGNAL_BYTES) {
      try { ws.close(1009, "signal too large"); } catch {}
      return;
    }

    const attachment = ws.deserializeAttachment();
    if (
      !attachment ||
      attachment.kind !== "peer" ||
      parseSignalRole(attachment.role) === null ||
      !Number.isSafeInteger(attachment.forwardedMessages) ||
      attachment.forwardedMessages < 0
    ) {
      try { ws.close(1008, "invalid peer state"); } catch {}
      return;
    }

    const terminal = parseSignalTerminalControl(message);
    switch (terminal.kind) {
      case "invalid-terminal":
        try { ws.close(1008, "invalid terminal signal"); } catch {}
        return;
      case "completed-elsewhere": {
        if (attachment.role !== "cli") {
          try { ws.close(1008, "terminal signal requires CLI role"); } catch {}
          return;
        }
        const transition = await this.completeSignalSessionElsewhere();
        switch (transition.kind) {
          case "published":
          case "already-published":
            return;
          case "expired":
            try { ws.close(1008, "signal session expired"); } catch {}
            return;
          case "invalid":
            await this.expireSignalSession();
            return;
        }
      }
      case "not-terminal":
        break;
    }

    if (attachment.forwardedMessages >= MAX_SIGNAL_MESSAGES_PER_SOCKET) {
      try { ws.close(1008, "too many signals"); } catch {}
      return;
    }

    const lifecycle = await this.requireActiveSignalSession();
    switch (lifecycle.kind) {
      case "expired":
        try { ws.close(1008, "signal session expired"); } catch {}
        return;
      case "completed-elsewhere":
        try { ws.close(1000, "session completed elsewhere"); } catch {}
        return;
      case "active":
        break;
    }

    /** @type {SignalRole} */
    const role = attachment.role;
    /** @type {SignalRole} */
    const destinationRole = role === "cli" ? "approver" : "cli";
    const destinations = this.socketsForRole(destinationRole);
    if (destinations.length !== 1) {
      try { ws.send(JSON.stringify({ type: "peer-not-ready" })); } catch {}
      return;
    }

    ws.serializeAttachment({
      kind: "peer",
      role,
      forwardedMessages: attachment.forwardedMessages + 1,
    });
    try {
      destinations[0].send(message);
    } catch {
      try { ws.send(JSON.stringify({ type: "peer-not-ready" })); } catch {}
    }
  }

  async alarm() {
    const lifecycle = parseSignalLifecycle(
      await this.state.storage.get(SIGNAL_LIFECYCLE_KEY),
    );
    switch (lifecycle.kind) {
      case "active":
      case "closed":
      case "completed-elsewhere":
        if (lifecycle.expiresAt > Date.now()) {
          // Alarm delivery is at-least-once; an early retry simply restores
          // the one-shot room's persisted deadline.
          await this.ensureLifecycleAlarm(lifecycle.expiresAt);
          return;
        }
        await this.expireSignalSession();
        return;
      case "missing":
      case "invalid":
        await this.expireSignalSession();
        return;
    }
  }

  async expireSignalSession() {
    for (const ws of this.state.getWebSockets()) {
      try { ws.close(1001, "session expired"); } catch {}
    }
    await this.state.storage.deleteAll();
  }

  async closeActiveSignalSession() {
    const transition = await this.state.storage.transaction(async (transaction) => {
      const lifecycle = parseSignalLifecycle(
        await transaction.get(SIGNAL_LIFECYCLE_KEY),
      );
      switch (lifecycle.kind) {
        case "invalid":
          return { kind: "invalid" };
        case "active":
          await transaction.put(SIGNAL_LIFECYCLE_KEY, {
            kind: "closed",
            expiresAt: lifecycle.expiresAt,
          });
          await transaction.delete(TURN_PASSKEY_CHALLENGE_KEY);
          await transaction.delete(TURN_CREDENTIAL_CACHE_KEY);
          return { kind: "closed" };
        case "missing":
        case "closed":
        case "completed-elsewhere":
          return { kind: "unchanged" };
      }
    });
    switch (transition.kind) {
      case "invalid":
        await this.expireSignalSession();
        return;
      case "unchanged":
        return;
      case "closed":
        break;
    }
    for (const ws of this.state.getWebSockets()) {
      const attachment = ws.deserializeAttachment();
      if (attachment?.kind === "peer") {
        try { ws.close(1001, "session expired"); } catch {}
      }
    }
  }

  /** @param {WebSocket} ws */
  async webSocketClose(ws) {
    const attachment = ws.deserializeAttachment();
    if (attachment?.kind === "peer" && attachment.role === "cli") {
      await this.closeActiveSignalSession();
    } else {
      this.notifyOtherPeerLeft(ws);
    }
    try { ws.close(); } catch {}
  }

  /** @param {WebSocket} ws */
  async webSocketError(ws) {
    const attachment = ws.deserializeAttachment();
    if (attachment?.kind === "peer" && attachment.role === "cli") {
      await this.closeActiveSignalSession();
    } else {
      this.notifyOtherPeerLeft(ws);
    }
    try { ws.close(1011, "error"); } catch {}
  }

  /** @param {WebSocket} ws */
  notifyOtherPeerLeft(ws) {
    const attachment = ws.deserializeAttachment();
    const role = parseSignalRole(attachment?.role ?? null);
    if (role === null) {
      return;
    }
    const destinationRole = role === "cli" ? "approver" : "cli";
    for (const peer of this.socketsForRole(destinationRole)) {
      try { peer.send(JSON.stringify({ type: "peer-left" })); } catch {}
    }
  }
}
