import assert from "node:assert/strict";
import test from "node:test";

import worker, { SignalSession } from "../src/index.js";

const RID = "A".repeat(43);
const ORIGIN = "https://keytap.jul.sh";
const LIFECYCLE_KEY = "signal:lifecycle";
const TURN_CREDENTIAL_CACHE_KEY = "turn:credential";
const TURN_PASSKEY_CHALLENGE_KEY = "turn:passkey-challenge";
const COMPLETED_ELSEWHERE_MESSAGE = '{"type":"completed-elsewhere"}';
const ALLOWED_CREDENTIAL_ID = "YMrfg78V4cqfr7NqwX_PkFZa13Y";
const ALLOWED_PUBLIC_KEY = "Fl1qDq-BqriovSqe40CPvq3rz6ltvoSoQM6gSuJfIsA";
const TEST_CREDENTIAL_ID = "Y3JlZGVudGlhbC1vd25lcg";
const TEST_PUBLIC_KEY = "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg";
const TEST_CAPABILITY =
  "Kq7yBsYegNIr5povtDGDpkwPryLT8KFBFKaBZ3Py_y1YaUBO7TGRq7yIrOUB6QWB0BYnU_XsGfCS59a8xRTLBg";
const TEST_CAPABILITY_HASH = "rnWKf-aH6uT0_84j6aPC6W5HQRK10aep8cSlOt9Aayc";
const TEST_PRIVATE_SEED = Uint8Array.from({ length: 32 }, (_, index) => index);
const ED25519_PKCS8_SEED_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);
const COMPLETION_PRIVATE_SEED = new Uint8Array(32).fill(7);

function authorizedEntitlement(capabilityHash = TEST_CAPABILITY_HASH) {
  return { kind: "authorized", capabilityHash };
}

function pendingEntitlement() {
  return { kind: "pending-passkey" };
}

function cliAdmission() {
  return { kind: "cli" };
}

class MemoryStorage {
  constructor() {
    this.values = new Map();
    this.alarm = null;
    this.transactionTail = Promise.resolve();
  }

  async get(key) { return this.values.get(key); }
  async put(key, value) { this.values.set(key, value); }
  async delete(key) { this.values.delete(key); }
  async deleteAll() {
    this.values.clear();
    this.alarm = null;
  }
  async deleteAlarm() { this.alarm = null; }
  async getAlarm() { return this.alarm; }
  async setAlarm(value) { this.alarm = value; }
  async transaction(operation) {
    let release;
    const previous = this.transactionTail;
    this.transactionTail = new Promise((resolve) => { release = resolve; });
    await previous;
    try {
      return await operation(this);
    } finally {
      release();
    }
  }
}

class FakeSocket {
  constructor(role) {
    this.attachment = { kind: "peer", role, forwardedMessages: 0 };
    this.sent = [];
    this.closed = [];
    this.readyState = WebSocket.OPEN;
  }

  serializeAttachment(value) { this.attachment = value; }
  deserializeAttachment() { return this.attachment; }
  send(value) { this.sent.push(value); }
  close(...args) {
    this.closed.push(args);
    this.readyState = WebSocket.CLOSING;
  }
}

class FakeState {
  constructor() {
    this.storage = new MemoryStorage();
    this.sockets = { cli: [], approver: [] };
    this.acceptedSockets = [];
  }

  getWebSockets(tag) {
    if (tag === "cli" || tag === "approver") {
      return this.sockets[tag];
    }
    return [...new Set([
      ...this.sockets.cli,
      ...this.sockets.approver,
      ...this.acceptedSockets,
    ])];
  }

  acceptWebSocket(socket, tags = []) {
    this.acceptedSockets.push(socket);
    for (const tag of tags) {
      this.sockets[tag].push(socket);
    }
  }
}

function activateState(
  state,
  expiresAt = Date.now() + 20 * 60 * 1000,
  turnEntitlement = authorizedEntitlement(),
) {
  state.storage.values.set(LIFECYCLE_KEY, {
    kind: "active",
    expiresAt,
    turnEntitlement,
  });
  state.storage.alarm = expiresAt;
  return state;
}

function readyState(
  expiresAt = Date.now() + 20 * 60 * 1000,
  turnEntitlement = authorizedEntitlement(),
) {
  const state = new FakeState();
  activateState(state, expiresAt, turnEntitlement);
  state.sockets.cli.push(new FakeSocket("cli"));
  state.sockets.approver.push(new FakeSocket("approver"));
  return state;
}

function storeChallenge(
  state,
  challenge,
  expiresAt,
) {
  state.storage.values.set(TURN_PASSKEY_CHALLENGE_KEY, {
    kind: "issued",
    challenge,
    expiresAt,
  });
}

function turnRequest(authorization = `Bearer ${TEST_CAPABILITY}`) {
  const headers = { Origin: ORIGIN };
  if (authorization !== null) headers.Authorization = authorization;
  return new Request(`https://signal.test/signal/${RID}/turn`, {
    headers,
  });
}

function turnEnvironment() {
  return {
    TURN_KEY_ID: "turn-key-id",
    TURN_KEY_API_TOKEN: "turn-api-token",
  };
}

async function withUpgradeRuntime(operation) {
  const NativeResponse = globalThis.Response;
  const NativeWebSocketPair = globalThis.WebSocketPair;

  class UpgradeResponse {
    constructor(body, init = {}) {
      if (init.status !== 101) return new NativeResponse(body, init);
      this.status = 101;
      this.headers = new Headers(init.headers);
      this.webSocket = init.webSocket;
    }
  }

  class TestWebSocketPair {
    constructor() {
      this.client = { kind: "upgrade-client" };
      this.server = new FakeSocket("cli");
    }
  }

  globalThis.Response = UpgradeResponse;
  globalThis.WebSocketPair = TestWebSocketPair;
  try {
    return await operation();
  } finally {
    globalThis.Response = NativeResponse;
    if (NativeWebSocketPair === undefined) delete globalThis.WebSocketPair;
    else globalThis.WebSocketPair = NativeWebSocketPair;
  }
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function decodeBase64Url(value) {
  return Uint8Array.from(Buffer.from(value, "base64url"));
}

function u32(value) {
  const result = new Uint8Array(4);
  new DataView(result.buffer).setUint32(0, value, false);
  return result;
}

function u64(value) {
  const result = new Uint8Array(8);
  new DataView(result.buffer).setBigUint64(0, BigInt(value), false);
  return result;
}

function concatenate(...values) {
  const result = new Uint8Array(values.reduce((sum, value) => sum + value.length, 0));
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}

function lengthPrefixed(value) {
  return concatenate(u32(value.length), value);
}

function passkeyAuthorizationMessage({
  rendezvousId,
  challenge,
  expiresAt,
  credentialId,
  publicKey,
}) {
  const encoder = new TextEncoder();
  return concatenate(
    encoder.encode("keytap:turn-passkey-authorization:v1\0"),
    lengthPrefixed(encoder.encode(rendezvousId)),
    lengthPrefixed(decodeBase64Url(challenge)),
    u64(expiresAt),
    lengthPrefixed(decodeBase64Url(credentialId)),
    lengthPrefixed(decodeBase64Url(publicKey)),
  );
}

function completionSignatureMessage(rendezvousId) {
  const encoder = new TextEncoder();
  return concatenate(
    encoder.encode("keytap:signal-completion:v1\0"),
    lengthPrefixed(encoder.encode(rendezvousId)),
  );
}

async function completionProof(privateSeed = COMPLETION_PRIVATE_SEED) {
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    concatenate(ED25519_PKCS8_SEED_PREFIX, privateSeed),
    { name: "Ed25519" },
    true,
    ["sign"],
  );
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  const publicKey = decodeBase64Url(jwk.x);
  const rendezvousId = base64Url(new Uint8Array(await crypto.subtle.digest(
    "SHA-256",
    concatenate(
      new TextEncoder().encode("keytap:rendezvous:v1\0"),
      publicKey,
    ),
  )));
  const signature = new Uint8Array(await crypto.subtle.sign(
    { name: "Ed25519" },
    privateKey,
    completionSignatureMessage(rendezvousId),
  ));
  return {
    rendezvousId,
    body: {
      v: 1,
      from: "cli",
      kind: "completed-elsewhere",
      publicKey: jwk.x,
      signature: base64Url(signature),
    },
  };
}

function completionRequest(rendezvousId, body, method = "POST") {
  return new Request(
    `https://signal.test/signal/${rendezvousId}/complete`,
    {
      method,
      headers: { "Content-Type": "application/json" },
      body: method === "POST" ? JSON.stringify(body) : undefined,
    },
  );
}

async function passkeyProof({
  rendezvousId = RID,
  challenge,
  expiresAt,
  credentialId = TEST_CREDENTIAL_ID,
  publicKey = TEST_PUBLIC_KEY,
  privateSeed = TEST_PRIVATE_SEED,
} = {}) {
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    concatenate(ED25519_PKCS8_SEED_PREFIX, privateSeed),
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  const message = passkeyAuthorizationMessage({
    rendezvousId,
    challenge,
    expiresAt,
    credentialId,
    publicKey,
  });
  const signature = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" }, privateKey, message),
  );
  return {
    kind: "turn-passkey-proof",
    challenge,
    expiresAt,
    credentialId,
    publicKey,
    signature: base64Url(signature),
  };
}

async function capabilityHash(signature) {
  return base64Url(new Uint8Array(
    await crypto.subtle.digest("SHA-256", decodeBase64Url(signature)),
  ));
}

function challengeRequest(body) {
  const init = {
    method: "POST",
    headers: { Origin: ORIGIN },
  };
  if (body !== undefined) init.body = body;
  return new Request(
    `https://signal.test/signal/${RID}/turn/challenge`,
    init,
  );
}

function authorizeRequest(proof) {
  return new Request(
    `https://signal.test/signal/${RID}/turn/authorize`,
    {
      method: "POST",
      headers: { Origin: ORIGIN, "Content-Type": "application/json" },
      body: JSON.stringify(proof),
    },
  );
}

const TURN_RESPONSE = {
  iceServers: [
    { urls: ["stun:stun.cloudflare.com:3478"] },
    {
      urls: ["turn:turn.cloudflare.com:3478?transport=udp"],
      username: "temporary-user",
      credential: "temporary-password",
    },
  ],
};

test("signal routes a valid rendezvous ID to its SignalSession object", async () => {
  let forwarded = null;
  const expected = new Response("signal object", { status: 200 });
  const request = new Request(`https://signal.test/signal/${RID}/turn`);
  const response = await worker.fetch(request, {
    SIGNAL_SESSION: {
      idFromName(name) {
        assert.equal(name, RID);
        return "signal-object-id";
      },
      get(id) {
        assert.equal(id, "signal-object-id");
        return {
          fetch(value) {
            forwarded = value;
            return expected;
          },
        };
      },
    },
  });

  assert.equal(response, expected);
  assert.equal(forwarded, request);
});

test("signal routes signed completion to the same SignalSession object", async () => {
  let forwarded = null;
  const expected = new Response("completed", { status: 200 });
  const request = new Request(
    `https://signal.test/signal/${RID}/complete`,
    { method: "POST", body: "{}" },
  );
  const response = await worker.fetch(request, {
    SIGNAL_SESSION: {
      idFromName(name) {
        assert.equal(name, RID);
        return "signal-object-id";
      },
      get(id) {
        assert.equal(id, "signal-object-id");
        return {
          fetch(value) {
            forwarded = value;
            return expected;
          },
        };
      },
    },
  });

  assert.equal(response, expected);
  assert.equal(forwarded, request);
});

test("signal routing accepts only canonical current paths", async () => {
  const requests = [
    new Request(`https://signal.test/signal/${"B".repeat(43)}`),
    new Request(`https://signal.test/signal/${RID}/`),
    new Request(`https://signal.test/signal/${RID}/unknown`),
    new Request(`https://signal.test/signal/${RID}/turn/challenge/extra`),
  ];

  for (const request of requests) {
    const response = await worker.fetch(request, {});
    assert.equal(response.status, 404, request.url);
    assert.equal(await response.text(), "Not found", request.url);
  }
});

test("TURN preflight advertises the Authorization request header", async () => {
  const response = await worker.fetch(new Request(
    `https://signal.test/signal/${RID}/turn`,
    {
      method: "OPTIONS",
      headers: {
        Origin: ORIGIN,
        "Access-Control-Request-Headers": "authorization",
      },
    },
  ), {});

  assert.equal(response.status, 204);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
  assert.equal(
    response.headers.get("Access-Control-Allow-Headers"),
    "Content-Type, Authorization",
  );
});

test("a signaling room caps each role at one connected socket", async () => {
  const state = activateState(new FakeState());
  state.sockets.cli.push(new FakeSocket("cli"));
  const session = new SignalSession(state, turnEnvironment());
  const request = new Request(`https://signal.test/signal/${RID}?role=cli`, {
    headers: { Upgrade: "websocket" },
  });

  const response = await session.fetch(request);
  assert.equal(response.status, 409);
  assert.equal(await response.text(), "cli is already connected");
});

test("signaling admission requires one exact current role", async () => {
  const queries = [
    "",
    "?role=observer",
    "?role=cli&role=approver",
    "?role=cli&trace=1",
    "?Role=cli",
  ];

  for (const query of queries) {
    const state = new FakeState();
    const response = await new SignalSession(state, turnEnvironment()).fetch(
      new Request(`https://signal.test/signal/${RID}${query}`, {
        headers: { Upgrade: "websocket" },
      }),
    );
    assert.equal(response.status, 400, query);
    assert.equal(
      await response.text(),
      "query must contain exactly one role=cli or role=approver",
      query,
    );
    assert.equal(state.storage.values.size, 0, query);
  }
});

test("HTTP signal endpoints reject query parameters", async () => {
  const state = readyState();
  const response = await new SignalSession(state, turnEnvironment()).fetch(
    new Request(`https://signal.test/signal/${RID}/turn?cache=true`),
  );

  assert.equal(response.status, 400);
  assert.equal(await response.text(), "Query parameters are not allowed");
});

test("CLI upgrade creates a pending room without making signaling private", async () => {
  await withUpgradeRuntime(async () => {
    const state = new FakeState();
    const session = new SignalSession(state, turnEnvironment());
    const response = await session.fetch(new Request(
      `https://signal.test/signal/${RID}?role=cli`,
      {
        headers: {
          Upgrade: "websocket",
          Authorization: "Bearer unexpected-upgrade-credential",
        },
      },
    ));

    assert.equal(response.status, 101);
    assert.deepEqual(
      state.storage.values.get(LIFECYCLE_KEY).turnEntitlement,
      pendingEntitlement(),
    );
    assert.equal(state.sockets.cli.length, 1);
  });
});

test("only the first CLI admission creates the one-shot room", async () => {
  const state = new FakeState();
  const session = new SignalSession(state, turnEnvironment());

  const beforeCreation = Date.now();
  const first = await session.beginOrJoinSignalSession(cliAdmission());
  const second = await session.beginOrJoinSignalSession(cliAdmission());
  const lifecycle = state.storage.values.get(LIFECYCLE_KEY);

  assert.equal(first.kind, "active");
  assert.ok(lifecycle.expiresAt >= beforeCreation + 1200 * 1000);
  assert.ok(lifecycle.expiresAt <= Date.now() + 1200 * 1000);
  assert.deepEqual(lifecycle.turnEntitlement, pendingEntitlement());
  assert.deepEqual(second, { kind: "duplicate-cli" });
  assert.equal(state.storage.alarm, lifecycle.expiresAt);
});

test("an approver cannot create a missing signaling room", async () => {
  const state = new FakeState();
  const session = new SignalSession(state, turnEnvironment());
  const request = new Request(`https://signal.test/signal/${RID}?role=approver`, {
    headers: { Upgrade: "websocket" },
  });

  const response = await session.fetch(request);

  assert.equal(response.status, 410);
  assert.equal(await response.text(), "Signal session expired");
  assert.equal(state.storage.values.has(LIFECYCLE_KEY), false);
});

test("an approver cannot join after the CLI signaling socket starts closing", async () => {
  const state = activateState(new FakeState());
  const cli = new FakeSocket("cli");
  cli.readyState = WebSocket.CLOSING;
  state.sockets.cli.push(cli);
  const session = new SignalSession(state, turnEnvironment());
  const request = new Request(`https://signal.test/signal/${RID}?role=approver`, {
    headers: { Upgrade: "websocket" },
  });

  const response = await session.fetch(request);

  assert.equal(response.status, 410);
  assert.equal(await response.text(), "CLI is no longer waiting");
  assert.equal(state.sockets.approver.length, 0);
});

test("CLI departure closes the one-shot room until its deadline", async () => {
  const state = readyState();
  const expiresAt = state.storage.alarm;
  const session = new SignalSession(state, turnEnvironment());

  await session.webSocketClose(state.sockets.cli[0]);

  assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), {
    kind: "closed",
    expiresAt,
  });
  assert.equal(state.storage.alarm, expiresAt);
  assert.deepEqual(state.sockets.approver[0].closed, [[1001, "session expired"]]);
  const retry = await session.fetch(new Request(
    `https://signal.test/signal/${RID}?role=cli`,
    { headers: { Upgrade: "websocket" } },
  ));
  assert.equal(retry.status, 410);
  assert.equal(await retry.text(), "Signal session expired");
});

test("CLI signaling error closes the one-shot room", async () => {
  const state = readyState();
  const expiresAt = state.storage.alarm;
  const session = new SignalSession(state, turnEnvironment());

  await session.webSocketError(state.sockets.cli[0]);

  assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), {
    kind: "closed",
    expiresAt,
  });
  assert.equal(state.storage.alarm, expiresAt);
  assert.deepEqual(state.sockets.approver[0].closed, [[1001, "session expired"]]);
});

test("CLI terminal signal persists completion before notifying connected peers", async () => {
  const state = readyState();
  const expiresAt = state.storage.values.get(LIFECYCLE_KEY).expiresAt;
  state.storage.values.set(TURN_PASSKEY_CHALLENGE_KEY, {
    kind: "issued",
    challenge: "A".repeat(43),
    expiresAt,
  });
  state.storage.values.set(TURN_CREDENTIAL_CACHE_KEY, {
    kind: "cached",
    capabilityHash: TEST_CAPABILITY_HASH,
    serialized: JSON.stringify(TURN_RESPONSE),
  });
  const cli = state.sockets.cli[0];
  const approver = state.sockets.approver[0];
  cli.attachment.forwardedMessages = 8;
  const session = new SignalSession(state, turnEnvironment());

  await session.webSocketMessage(cli, COMPLETED_ELSEWHERE_MESSAGE);

  assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), {
    kind: "completed-elsewhere",
    expiresAt,
  });
  assert.deepEqual([...state.storage.values.keys()], [LIFECYCLE_KEY]);
  assert.deepEqual(approver.sent, [COMPLETED_ELSEWHERE_MESSAGE]);
  assert.deepEqual(cli.closed, [[1000, "session completed elsewhere"]]);
  assert.deepEqual(approver.closed, [[1000, "session completed elsewhere"]]);
  assert.equal(cli.attachment.forwardedMessages, 8);

  await session.webSocketClose(cli);
  assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), {
    kind: "completed-elsewhere",
    expiresAt,
  });
});

test("CLI terminal still notifies live peers when tombstone alarm maintenance fails", async () => {
  const state = readyState();
  const expiresAt = state.storage.values.get(LIFECYCLE_KEY).expiresAt;
  state.storage.alarm = null;
  state.storage.setAlarm = async () => {
    throw new Error("alarm write failed");
  };
  const cli = state.sockets.cli[0];
  const approver = state.sockets.approver[0];
  const session = new SignalSession(state, turnEnvironment());

  await assert.rejects(
    session.webSocketMessage(cli, COMPLETED_ELSEWHERE_MESSAGE),
    /alarm write failed/,
  );

  assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), {
    kind: "completed-elsewhere",
    expiresAt,
  });
  assert.equal(state.storage.alarm, null);
  assert.deepEqual(approver.sent, [COMPLETED_ELSEWHERE_MESSAGE]);
  assert.deepEqual(cli.closed, [[1000, "session completed elsewhere"]]);
  assert.deepEqual(approver.closed, [[1000, "session completed elsewhere"]]);
});

test("a signed completion retires the live room before closing its approver", async () => {
  const proof = await completionProof();
  assert.deepEqual(proof, {
    rendezvousId: "kEJcshyj36SyT3e3fov2QqlBFMMRquKV0hgfhlqLIeI",
    body: {
      v: 1,
      from: "cli",
      kind: "completed-elsewhere",
      publicKey: "6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw",
      signature: "rAs3D7SL7tb5W4vSv_p8S0sMavfnGvFzCAahbjZ2cOz0Qo31MlsELG2Y0H00_HVh8iA-APlKKMHv9otvGLmiDQ",
    },
  });
  const state = readyState();
  const expiresAt = state.storage.values.get(LIFECYCLE_KEY).expiresAt;
  storeChallenge(state, "A".repeat(43), expiresAt);
  state.storage.values.set(TURN_CREDENTIAL_CACHE_KEY, {
    kind: "cached",
    capabilityHash: TEST_CAPABILITY_HASH,
    serialized: JSON.stringify(TURN_RESPONSE),
  });
  const cli = state.sockets.cli[0];
  const approver = state.sockets.approver[0];
  const session = new SignalSession(state, turnEnvironment());

  const response = await session.fetch(
    completionRequest(proof.rendezvousId, proof.body),
  );

  assert.equal(response.status, 200);
  assert.equal(await response.text(), '{"kind":"completed-elsewhere"}');
  assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), {
    kind: "completed-elsewhere",
    expiresAt,
  });
  assert.deepEqual([...state.storage.values.keys()], [LIFECYCLE_KEY]);
  assert.deepEqual(approver.sent, [COMPLETED_ELSEWHERE_MESSAGE]);
  assert.deepEqual(cli.closed, [[1000, "session completed elsewhere"]]);
  assert.deepEqual(approver.closed, [[1000, "session completed elsewhere"]]);
});

test("a signed native completion upgrades a concurrently closed room", async () => {
  const proof = await completionProof();
  const state = readyState();
  const expiresAt = state.storage.alarm;
  const session = new SignalSession(state, turnEnvironment());
  await session.webSocketClose(state.sockets.cli[0]);

  const response = await session.fetch(
    completionRequest(proof.rendezvousId, proof.body),
  );

  assert.equal(response.status, 200);
  assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), {
    kind: "completed-elsewhere",
    expiresAt,
  });
});

test("signed completion still notifies live peers when tombstone alarm maintenance fails", async () => {
  const proof = await completionProof();
  const state = readyState();
  const expiresAt = state.storage.values.get(LIFECYCLE_KEY).expiresAt;
  state.storage.alarm = null;
  state.storage.setAlarm = async () => {
    throw new Error("alarm write failed");
  };
  const cli = state.sockets.cli[0];
  const approver = state.sockets.approver[0];
  const session = new SignalSession(state, turnEnvironment());

  await assert.rejects(
    session.fetch(completionRequest(proof.rendezvousId, proof.body)),
    /alarm write failed/,
  );

  assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), {
    kind: "completed-elsewhere",
    expiresAt,
  });
  assert.equal(state.storage.alarm, null);
  assert.deepEqual(approver.sent, [COMPLETED_ELSEWHERE_MESSAGE]);
  assert.deepEqual(cli.closed, [[1000, "session completed elsewhere"]]);
  assert.deepEqual(approver.closed, [[1000, "session completed elsewhere"]]);
});

test("a signed completion before CLI admission leaves an atomic terminal tombstone", async () => {
  const proof = await completionProof();
  const state = new FakeState();
  const session = new SignalSession(state, turnEnvironment());

  const response = await session.fetch(
    completionRequest(proof.rendezvousId, proof.body),
  );
  const terminal = state.storage.values.get(LIFECYCLE_KEY);
  const laterAdmission = await session.beginOrJoinSignalSession(cliAdmission());

  assert.equal(response.status, 200);
  assert.equal(terminal.kind, "completed-elsewhere");
  assert.deepEqual(laterAdmission, { kind: "completed-elsewhere" });
  assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), terminal);
});

test("signed completion rejects malformed, wrong-room, and unsigned callers", async () => {
  const proof = await completionProof();
  const cases = [
    ["malformed", { ...proof.body, extra: true }, proof.rendezvousId, 400],
    ["wrong room", proof.body, RID, 403],
    [
      "bad signature",
      {
        ...proof.body,
        signature: `${proof.body.signature[0] === "A" ? "B" : "A"}${proof.body.signature.slice(1)}`,
      },
      proof.rendezvousId,
      403,
    ],
  ];
  for (const [name, body, rendezvousId, status] of cases) {
    const state = readyState();
    const original = structuredClone(state.storage.values.get(LIFECYCLE_KEY));
    const response = await new SignalSession(state, turnEnvironment()).fetch(
      completionRequest(rendezvousId, body),
    );
    assert.equal(response.status, status, name);
    assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), original, name);
    assert.deepEqual(state.sockets.approver[0].sent, [], name);
    assert.deepEqual(state.sockets.approver[0].closed, [], name);
  }
});

test("signed completion accepts POST only", async () => {
  const proof = await completionProof();
  const response = await new SignalSession(
    new FakeState(),
    turnEnvironment(),
  ).fetch(completionRequest(proof.rendezvousId, proof.body, "GET"));
  assert.equal(response.status, 405);
  assert.equal(response.headers.get("Allow"), "POST");
});

test("only the CLI can send the byte-exact terminal signal", async () => {
  const unauthorized = readyState();
  const unauthorizedLifecycle = structuredClone(
    unauthorized.storage.values.get(LIFECYCLE_KEY),
  );
  await new SignalSession(unauthorized, turnEnvironment()).webSocketMessage(
    unauthorized.sockets.approver[0],
    COMPLETED_ELSEWHERE_MESSAGE,
  );
  assert.deepEqual(
    unauthorized.sockets.approver[0].closed,
    [[1008, "terminal signal requires CLI role"]],
  );
  assert.deepEqual(
    unauthorized.storage.values.get(LIFECYCLE_KEY),
    unauthorizedLifecycle,
  );

  for (const malformed of [
    '{ "type":"completed-elsewhere"}',
    '{"type":"completed-elsewhere","extra":true}',
    '{"type":"completed-elsewhere","type":"completed-elsewhere"}',
  ]) {
    const state = readyState();
    const lifecycle = structuredClone(state.storage.values.get(LIFECYCLE_KEY));
    await new SignalSession(state, turnEnvironment()).webSocketMessage(
      state.sockets.cli[0],
      malformed,
    );
    assert.deepEqual(
      state.sockets.cli[0].closed,
      [[1008, "invalid terminal signal"]],
      malformed,
    );
    assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), lifecycle, malformed);
    assert.deepEqual(state.sockets.approver[0].sent, [], malformed);
  }
});

test("a late approver receives the persisted terminal outcome over WebSocket", async () => {
  await withUpgradeRuntime(async () => {
    const state = new FakeState();
    const expiresAt = Date.now() + 20 * 60 * 1000;
    state.storage.values.set(LIFECYCLE_KEY, {
      kind: "completed-elsewhere",
      expiresAt,
    });
    state.storage.alarm = null;
    const session = new SignalSession(state, turnEnvironment());

    const response = await session.fetch(new Request(
      `https://signal.test/signal/${RID}?role=approver`,
      { headers: { Upgrade: "websocket" } },
    ));

    assert.equal(response.status, 101);
    assert.equal(state.acceptedSockets.length, 1);
    const terminal = state.acceptedSockets[0];
    assert.deepEqual(terminal.attachment, {
      kind: "terminal",
      outcome: "completed-elsewhere",
    });
    assert.deepEqual(terminal.sent, [COMPLETED_ELSEWHERE_MESSAGE]);
    assert.deepEqual(terminal.closed, [[1000, "session completed elsewhere"]]);
    assert.equal(state.storage.alarm, expiresAt);

    await session.webSocketClose(terminal);
    assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), {
      kind: "completed-elsewhere",
      expiresAt,
    });
  });
});

test("a terminal room blocks CLI revival and TURN allocation", async () => {
  const originalFetch = globalThis.fetch;
  let providerCalls = 0;
  globalThis.fetch = async () => {
    providerCalls += 1;
    return new Response(JSON.stringify(TURN_RESPONSE));
  };
  try {
    const state = new FakeState();
    const expiresAt = Date.now() + 20 * 60 * 1000;
    state.storage.values.set(LIFECYCLE_KEY, {
      kind: "completed-elsewhere",
      expiresAt,
    });
    const session = new SignalSession(state, turnEnvironment());

    const cli = await session.fetch(new Request(
      `https://signal.test/signal/${RID}?role=cli`,
      { headers: { Upgrade: "websocket" } },
    ));
    const turn = await session.fetch(turnRequest());

    assert.equal(cli.status, 410);
    assert.equal(await cli.text(), "Signal session completed elsewhere");
    assert.equal(turn.status, 410);
    assert.equal(await turn.text(), "Signal session completed elsewhere");
    assert.equal(providerCalls, 0);
    assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), {
      kind: "completed-elsewhere",
      expiresAt,
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("a terminal transition before TURN minting does not contact the provider", async () => {
  const originalFetch = globalThis.fetch;
  let providerCalls = 0;
  globalThis.fetch = async () => {
    providerCalls += 1;
    return new Response(JSON.stringify(TURN_RESPONSE));
  };

  try {
    const state = readyState();
    const lifecycle = structuredClone(state.storage.values.get(LIFECYCLE_KEY));
    const session = new SignalSession(state, turnEnvironment());
    await session.webSocketMessage(
      state.sockets.cli[0],
      COMPLETED_ELSEWHERE_MESSAGE,
    );
    const result = await session.turnCredentialForRoom(
      {
        kind: "configured",
        keyId: "turn-key-id",
        apiToken: "turn-api-token",
      },
      lifecycle,
    );

    assert.deepEqual(result, {
      kind: "completed-elsewhere",
      expiresAt: lifecycle.expiresAt,
    });
    assert.equal(providerCalls, 0);
    assert.equal(state.storage.values.has(TURN_CREDENTIAL_CACHE_KEY), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("a terminal transition cannot be overwritten by an in-flight TURN allocation", async () => {
  const originalFetch = globalThis.fetch;
  let markProviderStarted;
  let releaseProvider;
  const providerStarted = new Promise((resolve) => { markProviderStarted = resolve; });
  const providerGate = new Promise((resolve) => { releaseProvider = resolve; });
  globalThis.fetch = async () => {
    markProviderStarted();
    await providerGate;
    return new Response(JSON.stringify(TURN_RESPONSE));
  };
  try {
    const state = readyState();
    const expiresAt = state.storage.values.get(LIFECYCLE_KEY).expiresAt;
    const session = new SignalSession(state, turnEnvironment());
    const turnResponse = session.fetch(turnRequest());
    await providerStarted;

    await session.webSocketMessage(
      state.sockets.cli[0],
      COMPLETED_ELSEWHERE_MESSAGE,
    );
    releaseProvider();
    const response = await turnResponse;

    assert.equal(response.status, 410);
    assert.equal(await response.text(), "Signal session completed elsewhere");
    assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), {
      kind: "completed-elsewhere",
      expiresAt,
    });
    assert.equal(state.storage.values.has(TURN_CREDENTIAL_CACHE_KEY), false);
  } finally {
    releaseProvider();
    globalThis.fetch = originalFetch;
  }
});

test("a TURN request cannot create a missing signal session", async () => {
  const state = new FakeState();
  state.sockets.cli.push(new FakeSocket("cli"));
  state.sockets.approver.push(new FakeSocket("approver"));
  const session = new SignalSession(state, turnEnvironment());

  const response = await session.fetch(turnRequest());

  assert.equal(response.status, 410);
  assert.equal(await response.text(), "Signal session expired");
  assert.equal(state.storage.values.has(LIFECYCLE_KEY), false);
});

test("passkey authorization message matches the fixed interoperability vector", () => {
  const challenge = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";
  const expiresAt = 2_000_000_000_000;
  assert.equal(
    base64Url(passkeyAuthorizationMessage({
      rendezvousId: RID,
      challenge,
      expiresAt,
      credentialId: TEST_CREDENTIAL_ID,
      publicKey: TEST_PUBLIC_KEY,
    })),
    "a2V5dGFwOnR1cm4tcGFzc2tleS1hdXRob3JpemF0aW9uOnYxAAAAACtBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBAAAAICAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4_AAAB0alKIAAAAAAQY3JlZGVudGlhbC1vd25lcgAAACADoQe_884Qvh1w3RjnS8CZZ-TWMJulDV8d3IZkElUxuA",
  );
});

test("the checked-in passkey identity can authorize one room capability", async () => {
  const subtlePrototype = Object.getPrototypeOf(crypto.subtle);
  const originalVerify = subtlePrototype.verify;
  const challenge = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";
  const expiresAt = Date.now() + 60_000;
  const proof = {
    kind: "turn-passkey-proof",
    challenge,
    expiresAt,
    credentialId: ALLOWED_CREDENTIAL_ID,
    publicKey: ALLOWED_PUBLIC_KEY,
    signature: TEST_CAPABILITY,
  };
  let verifyCalls = 0;
  subtlePrototype.verify = async function(algorithm, key, signature, message) {
    verifyCalls += 1;
    assert.deepEqual(algorithm, { name: "Ed25519" });
    assert.equal(key.type, "public");
    assert.deepEqual(signature, decodeBase64Url(TEST_CAPABILITY));
    assert.deepEqual(
      message,
      passkeyAuthorizationMessage({
        rendezvousId: RID,
        challenge,
        expiresAt,
        credentialId: ALLOWED_CREDENTIAL_ID,
        publicKey: ALLOWED_PUBLIC_KEY,
      }),
    );
    return true;
  };
  try {
    const state = readyState(
      expiresAt + 60_000,
      pendingEntitlement(),
    );
    storeChallenge(state, challenge, expiresAt);
    const response = await new SignalSession(state, turnEnvironment())
      .fetch(authorizeRequest(proof));

    assert.equal(response.status, 200);
    assert.equal(await response.text(), '{"kind":"turn-authorized"}');
    assert.equal(response.headers.get("Cache-Control"), "no-store");
    assert.equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
    assert.deepEqual(
      state.storage.values.get(LIFECYCLE_KEY).turnEntitlement,
      authorizedEntitlement(),
    );
    assert.equal(verifyCalls, 1);
  } finally {
    subtlePrototype.verify = originalVerify;
  }
});

test("challenge issuance requires both peers and caches one bounded nonce", async () => {
  const originalDateNow = Date.now;
  Date.now = () => 1_900_000_000_000;
  try {
    const state = readyState(
      Date.now() + 20 * 60 * 1000,
      pendingEntitlement(),
    );
    const session = new SignalSession(state, turnEnvironment());
    const [first, second] = await Promise.all([
      session.fetch(challengeRequest()),
      session.fetch(challengeRequest()),
    ]);
    const firstBody = await first.json();
    const secondBody = await second.json();

    assert.equal(first.status, 200);
    assert.deepEqual(secondBody, firstBody);
    assert.equal(firstBody.kind, "turn-passkey-challenge");
    assert.deepEqual(
      Object.keys(firstBody).sort(),
      ["challenge", "expiresAt", "kind"],
    );
    assert.equal(decodeBase64Url(firstBody.challenge).length, 32);
    assert.equal(firstBody.expiresAt, Date.now() + 5 * 60 * 1000);
    assert.deepEqual(state.storage.values.get(TURN_PASSKEY_CHALLENGE_KEY), {
      kind: "issued",
      challenge: firstBody.challenge,
      expiresAt: firstBody.expiresAt,
    });

    const noApprover = activateState(
      new FakeState(),
      Date.now() + 20 * 60 * 1000,
      pendingEntitlement(),
    );
    noApprover.sockets.cli.push(new FakeSocket("cli"));
    const rejected = await new SignalSession(noApprover, turnEnvironment())
      .fetch(challengeRequest());
    assert.equal(rejected.status, 409);
    assert.equal(noApprover.storage.values.has(TURN_PASSKEY_CHALLENGE_KEY), false);

    const nonempty = await session.fetch(challengeRequest("{}"));
    assert.equal(nonempty.status, 400);
  } finally {
    Date.now = originalDateNow;
  }
});

test("pending rooms reject TURN as missing capability without contacting the provider", async () => {
  const originalFetch = globalThis.fetch;
  let providerCalls = 0;
  globalThis.fetch = async () => {
    providerCalls += 1;
    return new Response(JSON.stringify(TURN_RESPONSE));
  };
  try {
    const state = readyState(
      Date.now() + 20 * 60 * 1000,
      pendingEntitlement(),
    );
    const session = new SignalSession(state, turnEnvironment());
    for (const authorization of [
      null,
      "Bearer malformed",
      `Bearer ${TEST_CAPABILITY}`,
    ]) {
      const response = await session.fetch(turnRequest(authorization));
      assert.equal(response.status, 401);
      assert.equal(await response.text(), '{"kind":"turn-capability-invalid"}');
    }
    assert.equal(providerCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("bad passkey proofs use bounded denial classes and do not consume the challenge", async () => {
  const originalDateNow = Date.now;
  const originalFetch = globalThis.fetch;
  const now = 1_900_000_000_000;
  const challenge = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";
  const expiresAt = now + 60_000;
  Date.now = () => now;
  let providerCalls = 0;
  globalThis.fetch = async () => {
    providerCalls += 1;
    return new Response(JSON.stringify(TURN_RESPONSE));
  };
  try {
    const valid = await passkeyProof({ challenge, expiresAt });
    const cases = [
      ["missing fields", { kind: "turn-passkey-proof" }, 403, "turn-not-allowlisted"],
      ["extra field", { ...valid, extra: true }, 403, "turn-not-allowlisted"],
      ["wrong kind", { ...valid, kind: "other" }, 403, "turn-not-allowlisted"],
      ["wrong challenge", { ...valid, challenge: "A".repeat(43) }, 409, "turn-challenge-expired"],
      ["wrong expiry", { ...valid, expiresAt: expiresAt + 1 }, 409, "turn-challenge-expired"],
      ["unknown credential", {
        ...valid,
        credentialId: base64Url(new TextEncoder().encode("other")),
      }, 403, "turn-not-allowlisted"],
      ["padded public key", { ...valid, publicKey: `${valid.publicKey}=` }, 403, "turn-not-allowlisted"],
      ["bad signature", {
        ...valid,
        signature: `${valid.signature[0] === "A" ? "B" : "A"}${valid.signature.slice(1)}`,
      }, 403, "turn-not-allowlisted"],
      ["wrong rendezvous signature", await passkeyProof({
        rendezvousId: "B".repeat(43),
        challenge,
        expiresAt,
      }), 403, "turn-not-allowlisted"],
    ];

    for (const [name, proof, expectedStatus, expectedKind] of cases) {
      const state = readyState(
        now + 20 * 60 * 1000,
        pendingEntitlement(),
      );
      storeChallenge(state, challenge, expiresAt);
      const response = await new SignalSession(state, turnEnvironment())
        .fetch(authorizeRequest(proof));
      assert.equal(response.status, expectedStatus, name);
      assert.equal(await response.text(), `{"kind":"${expectedKind}"}`, name);
      assert.deepEqual(
        state.storage.values.get(LIFECYCLE_KEY).turnEntitlement,
        pendingEntitlement(),
        name,
      );
      assert.equal(
        state.storage.values.get(TURN_PASSKEY_CHALLENGE_KEY).challenge,
        challenge,
        name,
      );
    }
    assert.equal(providerCalls, 0);
  } finally {
    Date.now = originalDateNow;
    globalThis.fetch = originalFetch;
  }
});

test("a failed proof can be followed by a valid proof for the same challenge", async () => {
  const subtlePrototype = Object.getPrototypeOf(crypto.subtle);
  const originalVerify = subtlePrototype.verify;
  const challenge = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";
  const expiresAt = Date.now() + 60_000;
  const valid = await passkeyProof({
    challenge,
    expiresAt,
    credentialId: ALLOWED_CREDENTIAL_ID,
    publicKey: ALLOWED_PUBLIC_KEY,
  });
  const invalid = {
    ...valid,
    signature: `${valid.signature[0] === "A" ? "B" : "A"}${valid.signature.slice(1)}`,
  };
  const state = readyState(
    Date.now() + 20 * 60 * 1000,
    pendingEntitlement(),
  );
  storeChallenge(state, challenge, expiresAt);
  const session = new SignalSession(state, turnEnvironment());

  subtlePrototype.verify = async (_algorithm, _key, signature) =>
    base64Url(signature) === valid.signature;
  try {
    assert.equal((await session.fetch(authorizeRequest(invalid))).status, 403);
    assert.equal((await session.fetch(authorizeRequest(valid))).status, 200);
    assert.deepEqual(
      state.storage.values.get(LIFECYCLE_KEY).turnEntitlement,
      authorizedEntitlement(await capabilityHash(valid.signature)),
    );
  } finally {
    subtlePrototype.verify = originalVerify;
  }
});

test("TURN allowlisting matches one exact credential and public-key pair", async () => {
  const subtlePrototype = Object.getPrototypeOf(crypto.subtle);
  const originalVerify = subtlePrototype.verify;
  const challenge = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";
  const expiresAt = Date.now() + 60_000;
  const wrongCredential = await passkeyProof({
    challenge,
    expiresAt,
    credentialId: TEST_CREDENTIAL_ID,
    publicKey: ALLOWED_PUBLIC_KEY,
  });
  const wrongPublicKey = await passkeyProof({
    challenge,
    expiresAt,
    credentialId: ALLOWED_CREDENTIAL_ID,
    publicKey: TEST_PUBLIC_KEY,
  });
  let verifyCalls = 0;
  subtlePrototype.verify = async () => {
    verifyCalls += 1;
    return true;
  };
  try {
    for (const proof of [wrongCredential, wrongPublicKey]) {
      const state = readyState(
        Date.now() + 20 * 60 * 1000,
        pendingEntitlement(),
      );
      storeChallenge(state, challenge, expiresAt);
      const response = await new SignalSession(state, turnEnvironment())
        .fetch(authorizeRequest(proof));

      assert.equal(response.status, 403);
      assert.equal(await response.text(), '{"kind":"turn-not-allowlisted"}');
      assert.deepEqual(
        state.storage.values.get(LIFECYCLE_KEY).turnEntitlement,
        pendingEntitlement(),
      );
    }
    assert.equal(verifyCalls, 0);
  } finally {
    subtlePrototype.verify = originalVerify;
  }
});

test("concurrent verified proofs cannot overwrite one room capability", async () => {
  const subtlePrototype = Object.getPrototypeOf(crypto.subtle);
  const originalVerify = subtlePrototype.verify;
  const challenge = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";
  const expiresAt = Date.now() + 60_000;
  const firstProof = await passkeyProof({
    challenge,
    expiresAt,
    credentialId: ALLOWED_CREDENTIAL_ID,
    publicKey: ALLOWED_PUBLIC_KEY,
  });
  const secondProof = {
    ...firstProof,
    signature: base64Url(new Uint8Array(64).fill(9)),
  };
  const state = readyState(
    Date.now() + 20 * 60 * 1000,
    pendingEntitlement(),
  );
  storeChallenge(state, challenge, expiresAt);
  const session = new SignalSession(state, turnEnvironment());
  let releaseVerifications;
  const verificationGate = new Promise((resolve) => {
    releaseVerifications = resolve;
  });
  let verifyCalls = 0;
  subtlePrototype.verify = async () => {
    verifyCalls += 1;
    if (verifyCalls === 2) releaseVerifications();
    await verificationGate;
    return true;
  };
  try {
    const responses = await Promise.all([
      session.fetch(authorizeRequest(firstProof)),
      session.fetch(authorizeRequest(secondProof)),
    ]);
    assert.deepEqual(
      responses.map((response) => response.status).sort(),
      [200, 403],
    );
    const entitlement = state.storage.values.get(LIFECYCLE_KEY).turnEntitlement;
    assert.equal(entitlement.kind, "authorized");
    assert.ok(
      [
        await capabilityHash(firstProof.signature),
        await capabilityHash(secondProof.signature),
      ].includes(entitlement.capabilityHash),
    );
  } finally {
    releaseVerifications();
    subtlePrototype.verify = originalVerify;
  }
});

test("expired, missing, or mismatched challenges are stale rather than allowlist denials", async () => {
  const originalDateNow = Date.now;
  const subtlePrototype = Object.getPrototypeOf(crypto.subtle);
  const originalVerify = subtlePrototype.verify;
  const now = 1_900_000_000_000;
  const challenge = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";
  let verifyCalls = 0;
  Date.now = () => now;
  subtlePrototype.verify = async function(...args) {
    verifyCalls += 1;
    return originalVerify.call(this, ...args);
  };
  try {
    const expiredProof = await passkeyProof({ challenge, expiresAt: now });
    const expiredState = readyState(
      now + 20 * 60 * 1000,
      pendingEntitlement(),
    );
    storeChallenge(expiredState, challenge, now);
    const expired = await new SignalSession(expiredState, turnEnvironment())
      .fetch(authorizeRequest(expiredProof));
    assert.equal(expired.status, 409);
    assert.equal(await expired.text(), '{"kind":"turn-challenge-expired"}');

    const missingProof = await passkeyProof({
      challenge,
      expiresAt: now + 60_000,
    });
    const missing = readyState(
      now + 20 * 60 * 1000,
      pendingEntitlement(),
    );
    const noChallenge = await new SignalSession(missing, turnEnvironment())
      .fetch(authorizeRequest(missingProof));
    assert.equal(noChallenge.status, 409);
    assert.equal(await noChallenge.text(), '{"kind":"turn-challenge-expired"}');

    const oldProof = await passkeyProof({
      challenge,
      expiresAt: now + 60_000,
    });
    const replacement = readyState(
      now + 20 * 60 * 1000,
      pendingEntitlement(),
    );
    storeChallenge(replacement, "A".repeat(43), now + 60_000);
    const stale = await new SignalSession(replacement, turnEnvironment())
      .fetch(authorizeRequest(oldProof));
    assert.equal(stale.status, 409);
    assert.equal(await stale.text(), '{"kind":"turn-challenge-expired"}');
    assert.deepEqual(
      replacement.storage.values.get(LIFECYCLE_KEY).turnEntitlement,
      pendingEntitlement(),
    );
    assert.equal(verifyCalls, 0);
  } finally {
    Date.now = originalDateNow;
    subtlePrototype.verify = originalVerify;
  }
});

test("a challenge expiring during Ed25519 verification returns the stale response", async () => {
  const originalDateNow = Date.now;
  const subtlePrototype = Object.getPrototypeOf(crypto.subtle);
  const originalVerify = subtlePrototype.verify;
  let markVerifyStarted;
  let releaseVerify;
  const verifyStarted = new Promise((resolve) => { markVerifyStarted = resolve; });
  const verifyGate = new Promise((resolve) => { releaseVerify = resolve; });
  const now = 1_900_000_000_000;
  const expiresAt = now + 1_000;
  const challenge = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";
  let currentTime = now;
  Date.now = () => currentTime;
  subtlePrototype.verify = async function() {
    markVerifyStarted();
    await verifyGate;
    return true;
  };
  try {
    const proof = await passkeyProof({
      challenge,
      expiresAt,
      credentialId: ALLOWED_CREDENTIAL_ID,
      publicKey: ALLOWED_PUBLIC_KEY,
    });
    const state = readyState(
      now + 60_000,
      pendingEntitlement(),
    );
    storeChallenge(state, challenge, expiresAt);

    const responsePromise = new SignalSession(state, turnEnvironment())
      .fetch(authorizeRequest(proof));
    await verifyStarted;
    currentTime = expiresAt;
    releaseVerify();
    const response = await responsePromise;

    assert.equal(response.status, 409);
    assert.equal(await response.text(), '{"kind":"turn-challenge-expired"}');
    assert.equal(response.headers.get("Cache-Control"), "no-store");
    assert.equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN);
    assert.deepEqual(
      state.storage.values.get(LIFECYCLE_KEY).turnEntitlement,
      pendingEntitlement(),
    );
  } finally {
    Date.now = originalDateNow;
    subtlePrototype.verify = originalVerify;
    releaseVerify();
  }
});

test("a signal lifecycle expiring during Ed25519 verification returns 410", async () => {
  const originalDateNow = Date.now;
  const subtlePrototype = Object.getPrototypeOf(crypto.subtle);
  const originalVerify = subtlePrototype.verify;
  let markVerifyStarted;
  let releaseVerify;
  const verifyStarted = new Promise((resolve) => { markVerifyStarted = resolve; });
  const verifyGate = new Promise((resolve) => { releaseVerify = resolve; });
  const now = 1_900_000_000_000;
  const expiresAt = now + 1_000;
  const challenge = "ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8";
  let currentTime = now;
  Date.now = () => currentTime;
  subtlePrototype.verify = async function() {
    markVerifyStarted();
    await verifyGate;
    return true;
  };
  try {
    const proof = await passkeyProof({
      challenge,
      expiresAt,
      credentialId: ALLOWED_CREDENTIAL_ID,
      publicKey: ALLOWED_PUBLIC_KEY,
    });
    const state = readyState(
      expiresAt,
      pendingEntitlement(),
    );
    storeChallenge(state, challenge, expiresAt);

    const responsePromise = new SignalSession(state, turnEnvironment())
      .fetch(authorizeRequest(proof));
    await verifyStarted;
    currentTime = expiresAt;
    releaseVerify();
    const response = await responsePromise;

    assert.equal(response.status, 410);
    assert.equal(await response.text(), "Signal session expired");
    assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), {
      kind: "closed",
      expiresAt,
    });
    assert.deepEqual(state.sockets.cli[0].closed, [[1001, "session expired"]]);
    assert.deepEqual(state.sockets.approver[0].closed, [[1001, "session expired"]]);
  } finally {
    Date.now = originalDateNow;
    subtlePrototype.verify = originalVerify;
    releaseVerify();
  }
});

test("challenge issuance fails closed for invalid TURN provider config", async () => {
  const cases = [
    ["missing", {}],
    ["missing key ID", { TURN_KEY_API_TOKEN: "turn-api-token" }],
    ["missing API token", { TURN_KEY_ID: "turn-key-id" }],
    ["empty key ID", {
      TURN_KEY_ID: "",
      TURN_KEY_API_TOKEN: "turn-api-token",
    }],
    ["empty API token", {
      TURN_KEY_ID: "turn-key-id",
      TURN_KEY_API_TOKEN: "",
    }],
    ["non-string key ID", {
      TURN_KEY_ID: 7,
      TURN_KEY_API_TOKEN: "turn-api-token",
    }],
  ];

  for (const [name, env] of cases) {
    const state = readyState(
      Date.now() + 20 * 60 * 1000,
      pendingEntitlement(),
    );
    const response = await new SignalSession(state, env).fetch(challengeRequest());
    assert.equal(response.status, 503, name);
    assert.equal(await response.text(), '{"kind":"turn-configuration-error"}', name);
    assert.equal(state.storage.values.has(TURN_PASSKEY_CHALLENGE_KEY), false, name);
  }
});

test("TURN credentials require the exact proof-signature bearer capability", async () => {
  const originalFetch = globalThis.fetch;
  let providerCalls = 0;
  globalThis.fetch = async () => {
    providerCalls += 1;
    return new Response(JSON.stringify(TURN_RESPONSE));
  };
  const wrongCapability = base64Url(new Uint8Array(64).fill(7));
  const cases = [
    ["missing", null],
    ["wrong scheme", `bearer ${TEST_CAPABILITY}`],
    ["extra whitespace", `Bearer  ${TEST_CAPABILITY}`],
    ["padded", `Bearer ${TEST_CAPABILITY}=`],
    ["short", "Bearer AA"],
    ["wrong", `Bearer ${wrongCapability}`],
  ];

  try {
    assert.equal(await capabilityHash(TEST_CAPABILITY), TEST_CAPABILITY_HASH);
    for (const [name, authorization] of cases) {
      const state = readyState();
      state.storage.values.set(TURN_CREDENTIAL_CACHE_KEY, {
        kind: "cached",
        capabilityHash: TEST_CAPABILITY_HASH,
        serialized: JSON.stringify(TURN_RESPONSE),
      });
      const response = await new SignalSession(state, turnEnvironment())
        .fetch(turnRequest(authorization));

      assert.equal(response.status, 401, name);
      assert.equal(await response.text(), '{"kind":"turn-capability-invalid"}', name);
      assert.equal(response.headers.get("Cache-Control"), "no-store", name);
      assert.equal(response.headers.get("Access-Control-Allow-Origin"), ORIGIN, name);
    }
    assert.equal(providerCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("an authorized entitlement without a canonical capability hash expires closed", async () => {
  const originalFetch = globalThis.fetch;
  let providerCalls = 0;
  globalThis.fetch = async () => {
    providerCalls += 1;
    return new Response(JSON.stringify(TURN_RESPONSE));
  };
  try {
    const invalidEntitlements = [
      { kind: "authorized" },
      {
        kind: "authorized",
        capabilityHash: `${TEST_CAPABILITY_HASH}=`,
      },
      {
        kind: "authorized",
        capabilityHash: TEST_CAPABILITY_HASH,
        identity: TEST_PUBLIC_KEY,
      },
    ];
    for (const turnEntitlement of invalidEntitlements) {
      const state = readyState();
      state.storage.values.get(LIFECYCLE_KEY).turnEntitlement = turnEntitlement;
      const response = await new SignalSession(state, turnEnvironment())
        .fetch(turnRequest());

      assert.equal(response.status, 410);
      assert.equal(await response.text(), "Signal session expired");
      assert.equal(state.storage.values.size, 0);
    }
    assert.equal(providerCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("malformed or capability-mismatched TURN caches fail closed", async () => {
  const originalFetch = globalThis.fetch;
  let providerCalls = 0;
  globalThis.fetch = async () => {
    providerCalls += 1;
    return new Response(JSON.stringify(TURN_RESPONSE));
  };
  const otherCapabilityHash = base64Url(new Uint8Array(32).fill(9));
  const cases = [
    ["malformed", {
      kind: "cached",
      serialized: JSON.stringify(TURN_RESPONSE),
    }],
    ["wrong capability", {
      kind: "cached",
      capabilityHash: otherCapabilityHash,
      serialized: JSON.stringify(TURN_RESPONSE),
    }],
    ["extra identity field", {
      kind: "cached",
      identity: TEST_PUBLIC_KEY,
      capabilityHash: TEST_CAPABILITY_HASH,
      serialized: JSON.stringify(TURN_RESPONSE),
    }],
  ];

  try {
    for (const [name, cached] of cases) {
      const state = readyState();
      state.storage.values.set(TURN_CREDENTIAL_CACHE_KEY, cached);
      const response = await new SignalSession(state, turnEnvironment())
        .fetch(turnRequest());

      assert.equal(response.status, 503, name);
      assert.equal(await response.text(), '{"kind":"turn-configuration-error"}', name);
      assert.deepEqual(state.storage.values.get(TURN_CREDENTIAL_CACHE_KEY), cached, name);
    }
    assert.equal(providerCalls, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("TURN credentials use a fixed TTL and are cached once per room", async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(TURN_RESPONSE), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  };

  try {
    const state = readyState();
    const session = new SignalSession(state, turnEnvironment());

    const first = await session.fetch(turnRequest());
    const second = await new SignalSession(state, turnEnvironment()).fetch(turnRequest());

    assert.equal(first.status, 200);
    assert.deepEqual(await first.json(), TURN_RESPONSE);
    assert.deepEqual(await second.json(), TURN_RESPONSE);
    assert.equal(first.headers.get("Cache-Control"), "no-store, private");
    assert.equal(first.headers.get("Access-Control-Allow-Origin"), ORIGIN);
    assert.equal(calls.length, 1);
    assert.equal(
      calls[0].url,
      "https://rtc.live.cloudflare.com/v1/turn/keys/turn-key-id/credentials/generate-ice-servers",
    );
    assert.equal(calls[0].init.headers.Authorization, "Bearer turn-api-token");
    assert.deepEqual(JSON.parse(calls[0].init.body), { ttl: 1200 });
    assert.deepEqual(
      [...state.storage.values.keys()],
      [LIFECYCLE_KEY, TURN_CREDENTIAL_CACHE_KEY],
    );
    assert.deepEqual(state.storage.values.get(TURN_CREDENTIAL_CACHE_KEY), {
      kind: "cached",
      capabilityHash: TEST_CAPABILITY_HASH,
      serialized: JSON.stringify(TURN_RESPONSE),
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("concurrent TURN reads share one provider allocation", async () => {
  const originalFetch = globalThis.fetch;
  let markProviderStarted;
  let releaseProvider;
  const providerStarted = new Promise((resolve) => { markProviderStarted = resolve; });
  const providerGate = new Promise((resolve) => { releaseProvider = resolve; });
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    markProviderStarted();
    await providerGate;
    return new Response(JSON.stringify(TURN_RESPONSE));
  };

  try {
    const state = readyState();
    const session = new SignalSession(state, turnEnvironment());
    const first = session.fetch(turnRequest());
    const second = session.fetch(turnRequest());

    await providerStarted;
    assert.equal(calls, 1);
    releaseProvider();

    const responses = await Promise.all([first, second]);
    assert.deepEqual(await responses[0].json(), TURN_RESPONSE);
    assert.deepEqual(await responses[1].json(), TURN_RESPONSE);
    assert.equal(calls, 1);
  } finally {
    releaseProvider();
    globalThis.fetch = originalFetch;
  }
});

test("CLI close cannot split an unresolved TURN allocation", async () => {
  const originalFetch = globalThis.fetch;
  let markProviderStarted;
  let releaseProvider;
  const providerStarted = new Promise((resolve) => { markProviderStarted = resolve; });
  const providerGate = new Promise((resolve) => { releaseProvider = resolve; });
  let providerCalls = 0;
  globalThis.fetch = async () => {
    providerCalls += 1;
    markProviderStarted();
    await providerGate;
    return new Response(JSON.stringify(TURN_RESPONSE));
  };

  try {
    const state = readyState();
    const lifecycle = structuredClone(state.storage.values.get(LIFECYCLE_KEY));
    const session = new SignalSession(state, turnEnvironment());
    const config = {
      kind: "configured",
      keyId: "turn-key-id",
      apiToken: "turn-api-token",
    };

    const first = session.turnCredentialForRoom(config, lifecycle);
    await providerStarted;
    await session.webSocketClose(state.sockets.cli[0]);
    const second = session.turnCredentialForRoom(config, lifecycle);
    assert.equal(providerCalls, 1);

    releaseProvider();
    assert.deepEqual(await Promise.all([first, second]), [
      { kind: "expired" },
      { kind: "expired" },
    ]);
    assert.equal(providerCalls, 1);
    assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), {
      kind: "closed",
      expiresAt: lifecycle.expiresAt,
    });
    assert.equal(state.storage.values.has(TURN_CREDENTIAL_CACHE_KEY), false);
  } finally {
    releaseProvider();
    globalThis.fetch = originalFetch;
  }
});

test("TURN reads stay coalesced until the credential cache write completes", async () => {
  const originalFetch = globalThis.fetch;
  let releaseCacheWrite;
  let calls = 0;
  globalThis.fetch = async () => {
    calls += 1;
    return new Response(JSON.stringify(TURN_RESPONSE));
  };

  try {
    const state = readyState();
    const originalPut = state.storage.put.bind(state.storage);
    let markCacheWriteStarted;
    const cacheWriteStarted = new Promise((resolve) => { markCacheWriteStarted = resolve; });
    const cacheWriteGate = new Promise((resolve) => { releaseCacheWrite = resolve; });
    state.storage.put = async (key, value) => {
      if (key === TURN_CREDENTIAL_CACHE_KEY) {
        markCacheWriteStarted();
        await cacheWriteGate;
      }
      return originalPut(key, value);
    };

    const session = new SignalSession(state, turnEnvironment());
    const originalTurnCredentialForRoom =
      session.turnCredentialForRoom.bind(session);
    let coordinatorCalls = 0;
    let markSecondCoordinatorCall;
    const secondCoordinatorCall = new Promise((resolve) => {
      markSecondCoordinatorCall = resolve;
    });
    session.turnCredentialForRoom = (...args) => {
      coordinatorCalls += 1;
      if (coordinatorCalls === 2) markSecondCoordinatorCall();
      return originalTurnCredentialForRoom(...args);
    };
    const first = session.fetch(turnRequest());
    await cacheWriteStarted;
    const second = session.fetch(turnRequest());
    await secondCoordinatorCall;

    assert.equal(calls, 1);
    releaseCacheWrite();
    const responses = await Promise.all([first, second]);
    assert.equal(responses[0].status, 200);
    assert.equal(responses[1].status, 200);
    assert.equal(calls, 1);
  } finally {
    releaseCacheWrite();
    globalThis.fetch = originalFetch;
  }
});

test("a delayed TURN response cannot resurrect an expired session", async () => {
  const originalFetch = globalThis.fetch;
  let markProviderStarted;
  let releaseProvider;
  const providerStarted = new Promise((resolve) => { markProviderStarted = resolve; });
  const providerGate = new Promise((resolve) => { releaseProvider = resolve; });
  globalThis.fetch = async () => {
    markProviderStarted();
    await providerGate;
    return new Response(JSON.stringify(TURN_RESPONSE));
  };

  try {
    const state = readyState();
    const session = new SignalSession(state, turnEnvironment());
    const pending = session.fetch(turnRequest());

    await providerStarted;
    activateState(state, Date.now() - 1);
    await session.alarm();
    assert.equal(session.turnCredentialMint.kind, "pending");
    releaseProvider();

    const response = await pending;
    assert.equal(response.status, 410);
    assert.equal(await response.text(), "Signal session expired");
    assert.equal(session.turnCredentialMint.kind, "idle");
    assert.equal(state.storage.values.size, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("the persisted deadline rejects TURN before contacting the provider", async () => {
  const originalFetch = globalThis.fetch;
  let providerCalls = 0;
  globalThis.fetch = async () => {
    providerCalls += 1;
    return new Response(JSON.stringify(TURN_RESPONSE));
  };

  try {
    const state = readyState();
    activateState(state, Date.now() - 1);
    const session = new SignalSession(state, turnEnvironment());

    const response = await session.fetch(turnRequest());

    assert.equal(response.status, 410);
    assert.equal(await response.text(), "Signal session expired");
    assert.equal(providerCalls, 0);
    assert.equal(state.storage.values.size, 0);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("provider errors are not reflected to callers", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response("provider secret detail", { status: 401 });

  try {
    const state = readyState();
    const session = new SignalSession(state, turnEnvironment());
    const response = await session.fetch(turnRequest());

    assert.equal(response.status, 502);
    assert.equal(await response.text(), "TURN credential provider failed");
    assert.deepEqual([...state.storage.values.keys()], [LIFECYCLE_KEY]);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("signaling forwards exact bounded text only to the opposite role", async () => {
  const state = readyState();
  const session = new SignalSession(state, turnEnvironment());
  const cli = state.sockets.cli[0];
  const approver = state.sockets.approver[0];
  const envelope = JSON.stringify({ v: 1, body: "opaque signaling payload" });

  await session.webSocketMessage(cli, envelope);
  assert.deepEqual(approver.sent, [envelope]);
  assert.equal(cli.attachment.forwardedMessages, 1);

  await session.webSocketMessage(cli, "x".repeat(128 * 1024 + 1));
  assert.deepEqual(cli.closed.at(-1), [1009, "signal too large"]);
  assert.deepEqual(approver.sent, [envelope]);
});

test("signaling caps the number of frames forwarded by each socket", async () => {
  const state = readyState();
  const session = new SignalSession(state, turnEnvironment());
  const cli = state.sockets.cli[0];
  const approver = state.sockets.approver[0];

  for (let index = 0; index < 8; index += 1) {
    await session.webSocketMessage(cli, `signal-${index}`);
  }
  assert.equal(approver.sent.length, 8);

  await session.webSocketMessage(cli, "signal-8");
  assert.equal(approver.sent.length, 8);
  assert.deepEqual(cli.closed.at(-1), [1008, "too many signals"]);
});

test("session alarm closes peers and erases the lifecycle", async () => {
  const state = readyState(Date.now() - 1);
  const session = new SignalSession(state, turnEnvironment());

  await session.alarm();

  assert.equal(state.storage.values.size, 0);
  assert.deepEqual(state.sockets.cli[0].closed, [[1001, "session expired"]]);
  assert.deepEqual(state.sockets.approver[0].closed, [[1001, "session expired"]]);
});

test("terminal tombstones survive early alarms and are erased at their deadline", async () => {
  for (const kind of ["closed", "completed-elsewhere"]) {
    const state = new FakeState();
    const expiresAt = Date.now() + 20 * 60 * 1000;
    state.storage.values.set(LIFECYCLE_KEY, { kind, expiresAt });
    const session = new SignalSession(state, turnEnvironment());

    await session.alarm();
    assert.deepEqual(
      state.storage.values.get(LIFECYCLE_KEY),
      { kind, expiresAt },
    );
    assert.equal(state.storage.alarm, expiresAt);

    state.storage.values.get(LIFECYCLE_KEY).expiresAt = Date.now() - 1;
    await session.alarm();
    assert.equal(state.storage.values.size, 0);
    assert.equal(state.storage.alarm, null);
  }
});
