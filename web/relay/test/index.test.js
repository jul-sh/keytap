import assert from "node:assert/strict";
import test from "node:test";

import worker, { SignalSession } from "../src/index.js";

const RID = "A".repeat(43);
const ORIGIN = "https://keytap.jul.sh";
const GENERATION = "test-generation";
const LIFECYCLE_KEY = "signal:lifecycle";

class MemoryStorage {
  constructor() {
    this.values = new Map();
    this.alarm = null;
  }

  async get(key) { return this.values.get(key); }
  async put(key, value) { this.values.set(key, value); }
  async deleteAll() { this.values.clear(); }
  async transaction(callback) { return callback(this); }
  async deleteAlarm() { this.alarm = null; }
  async getAlarm() { return this.alarm; }
  async setAlarm(value) { this.alarm = value; }
}

class FakeSocket {
  constructor(role, generation = GENERATION) {
    this.attachment = { kind: "peer", role, generation, forwardedMessages: 0 };
    this.sent = [];
    this.closed = [];
  }

  serializeAttachment(value) { this.attachment = value; }
  deserializeAttachment() { return this.attachment; }
  send(value) { this.sent.push(value); }
  close(...args) { this.closed.push(args); }
}

class FakeState {
  constructor() {
    this.storage = new MemoryStorage();
    this.sockets = { cli: [], phone: [] };
  }

  getWebSockets(tag) {
    if (tag === "cli" || tag === "phone") {
      return this.sockets[tag];
    }
    return [...this.sockets.cli, ...this.sockets.phone];
  }

  acceptWebSocket(socket, tags = []) {
    for (const tag of tags) {
      this.sockets[tag].push(socket);
    }
  }
}

function activateState(
  state,
  generation = GENERATION,
  expiresAt = Date.now() + 20 * 60 * 1000,
) {
  state.storage.values.set(LIFECYCLE_KEY, { kind: "active", generation, expiresAt });
  state.storage.alarm = expiresAt;
  return state;
}

function readyState(
  generation = GENERATION,
  expiresAt = Date.now() + 20 * 60 * 1000,
) {
  const state = new FakeState();
  activateState(state, generation, expiresAt);
  state.sockets.cli.push(new FakeSocket("cli", generation));
  state.sockets.phone.push(new FakeSocket("phone", generation));
  return state;
}

function turnRequest(role = "cli") {
  return new Request(`https://relay.test/v2/signal/${RID}/turn/${role}`, {
    headers: { Origin: ORIGIN },
  });
}

function turnEnvironment() {
  return {
    TURN_KEY_ID: "turn-key-id",
    TURN_KEY_API_TOKEN: "turn-api-token",
  };
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

test("legacy routes bypass v2 rate limiting and keep their relay namespace", async () => {
  let forwarded = null;
  const expected = new Response("legacy", { status: 200 });
  const env = {
    RELAY_SESSION: {
      idFromName(name) {
        assert.equal(name, "legacy-id");
        return "legacy-object-id";
      },
      get(id) {
        assert.equal(id, "legacy-object-id");
        return {
          fetch(request) {
            forwarded = request;
            return expected;
          },
        };
      },
    },
  };

  const request = new Request("https://relay.test/relay/legacy-id");
  const response = await worker.fetch(request, env);
  assert.equal(response, expected);
  assert.equal(forwarded, request);
});

test("v2 rejects a request when its per-IP rate limit is exhausted", async () => {
  const response = await worker.fetch(
    new Request(`https://relay.test/v2/signal/${RID}?role=cli`, {
      headers: { "CF-Connecting-IP": "192.0.2.1" },
    }),
    {
      SIGNAL_RATE_LIMIT: {
        async limit(input) {
          assert.deepEqual(input, { key: "signal:192.0.2.1" });
          return { success: false };
        },
      },
    },
  );

  assert.equal(response.status, 429);
  assert.equal(response.headers.get("Retry-After"), "60");
  assert.equal(response.headers.get("Cache-Control"), "no-store");
});

test("v2 routes a valid rendezvous ID to its SignalSession object", async () => {
  let forwarded = null;
  const expected = new Response("signal object", { status: 200 });
  const request = new Request(`https://relay.test/v2/signal/${RID}/turn/phone`, {
    headers: { "CF-Connecting-IP": "192.0.2.2" },
  });
  const response = await worker.fetch(request, {
    SIGNAL_RATE_LIMIT: { async limit() { return { success: true }; } },
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

test("a signaling room caps each role at one connected socket", async () => {
  const state = activateState(new FakeState());
  state.sockets.cli.push(new FakeSocket("cli"));
  const session = new SignalSession(state, turnEnvironment());
  const request = new Request(`https://relay.test/v2/signal/${RID}?role=cli`, {
    headers: { Upgrade: "websocket" },
  });

  const response = await session.fetch(request);
  assert.equal(response.status, 409);
  assert.equal(await response.text(), "cli is already connected");
});

test("WebSocket admission creates and reuses one persisted session generation", async () => {
  const state = new FakeState();
  const session = new SignalSession(state, turnEnvironment());

  const first = await session.beginOrJoinSignalSession();
  const second = await session.beginOrJoinSignalSession();

  assert.equal(first.kind, "active");
  assert.deepEqual(second, first);
  assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), first);
  assert.equal(state.storage.alarm, first.expiresAt);
});

test("TURN credentials require both roles to be connected", async () => {
  const state = activateState(new FakeState());
  state.sockets.cli.push(new FakeSocket("cli"));
  const session = new SignalSession(state, turnEnvironment());

  const response = await session.fetch(turnRequest());
  assert.equal(response.status, 409);
  assert.equal(await response.text(), "Both peers must be connected");
});

test("a TURN request cannot create a missing signal session", async () => {
  const state = new FakeState();
  state.sockets.cli.push(new FakeSocket("cli"));
  state.sockets.phone.push(new FakeSocket("phone"));
  const session = new SignalSession(state, turnEnvironment());

  const response = await session.fetch(turnRequest());

  assert.equal(response.status, 410);
  assert.equal(await response.text(), "Signal session expired");
  assert.equal(state.storage.values.has(LIFECYCLE_KEY), false);
});

test("TURN credentials use a fixed TTL and are minted once per role", async () => {
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

    const first = await session.fetch(turnRequest("cli"));
    const retry = await session.fetch(turnRequest("cli"));
    const phone = await session.fetch(turnRequest("phone"));

    assert.equal(first.status, 200);
    assert.deepEqual(await first.json(), TURN_RESPONSE);
    assert.deepEqual(await retry.json(), TURN_RESPONSE);
    assert.deepEqual(await phone.json(), TURN_RESPONSE);
    assert.equal(first.headers.get("Cache-Control"), "no-store, private");
    assert.equal(first.headers.get("Access-Control-Allow-Origin"), ORIGIN);
    assert.equal(calls.length, 2);
    assert.equal(
      calls[0].url,
      "https://rtc.live.cloudflare.com/v1/turn/keys/turn-key-id/credentials/generate-ice-servers",
    );
    assert.equal(calls[0].init.headers.Authorization, "Bearer turn-api-token");
    assert.deepEqual(JSON.parse(calls[0].init.body), { ttl: 1200 });
    assert.equal(typeof state.storage.values.get(`turn:${GENERATION}:cli`), "string");
    assert.equal(typeof state.storage.values.get(`turn:${GENERATION}:phone`), "string");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("concurrent retries share one TURN credential request", async () => {
  const originalFetch = globalThis.fetch;
  let providerCalls = 0;
  let releaseProvider;
  const providerGate = new Promise((resolve) => { releaseProvider = resolve; });
  globalThis.fetch = async () => {
    providerCalls += 1;
    await providerGate;
    return new Response(JSON.stringify(TURN_RESPONSE));
  };

  try {
    const session = new SignalSession(readyState(), turnEnvironment());
    const first = session.fetch(turnRequest());
    const second = session.fetch(turnRequest());
    await Promise.resolve();
    releaseProvider();

    assert.equal((await first).status, 200);
    assert.equal((await second).status, 200);
    assert.equal(providerCalls, 1);
  } finally {
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
    activateState(state, GENERATION, Date.now() - 1);
    await session.alarm();
    releaseProvider();

    const response = await pending;
    assert.equal(response.status, 410);
    assert.equal(await response.text(), "Signal session expired");
    assert.equal(
      [...state.storage.values.keys()].some((key) => key.startsWith("turn:")),
      false,
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("a recreated room neither commits nor shares the prior generation's mint", async () => {
  const originalFetch = globalThis.fetch;
  let providerCalls = 0;
  let markFirstProviderStarted;
  let markBothProvidersStarted;
  let releaseProviders;
  const firstProviderStarted = new Promise((resolve) => {
    markFirstProviderStarted = resolve;
  });
  const bothProvidersStarted = new Promise((resolve) => {
    markBothProvidersStarted = resolve;
  });
  const providerGate = new Promise((resolve) => { releaseProviders = resolve; });
  globalThis.fetch = async () => {
    providerCalls += 1;
    if (providerCalls === 1) markFirstProviderStarted();
    if (providerCalls === 2) markBothProvidersStarted();
    await providerGate;
    return new Response(JSON.stringify(TURN_RESPONSE));
  };

  try {
    const state = readyState("generation-a");
    const session = new SignalSession(state, turnEnvironment());
    const oldRequest = session.fetch(turnRequest());

    await firstProviderStarted;
    activateState(state, "generation-a", Date.now() - 1);
    await session.alarm();
    activateState(state, "generation-b");
    state.sockets.cli.push(new FakeSocket("cli", "generation-b"));
    state.sockets.phone.push(new FakeSocket("phone", "generation-b"));
    const newRequest = session.fetch(turnRequest());

    await bothProvidersStarted;
    assert.equal(providerCalls, 2);
    releaseProviders();

    const [oldResponse, newResponse] = await Promise.all([oldRequest, newRequest]);
    assert.equal(oldResponse.status, 410);
    assert.equal(newResponse.status, 200);
    assert.equal(state.storage.values.has("turn:generation-a:cli"), false);
    assert.equal(typeof state.storage.values.get("turn:generation-b:cli"), "string");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("a transaction retry cannot return a rolled-back TURN credential", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response(JSON.stringify(TURN_RESPONSE));

  try {
    const state = readyState();
    let transactionAttempts = 0;
    state.storage.transaction = async (callback) => {
      transactionAttempts += 1;
      const rolledBack = await callback(state.storage);
      assert.equal(rolledBack.kind, "stored");
      state.storage.values.delete(`turn:${GENERATION}:cli`);
      state.storage.values.delete(LIFECYCLE_KEY);

      transactionAttempts += 1;
      return callback(state.storage);
    };
    const session = new SignalSession(state, turnEnvironment());

    const response = await session.fetch(turnRequest());

    assert.equal(response.status, 410);
    assert.equal(await response.text(), "Signal session expired");
    assert.equal(transactionAttempts, 2);
    assert.equal(state.storage.values.has(`turn:${GENERATION}:cli`), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("the persisted deadline rejects cached TURN data before a delayed alarm", async () => {
  const originalFetch = globalThis.fetch;
  let providerCalls = 0;
  globalThis.fetch = async () => {
    providerCalls += 1;
    return new Response(JSON.stringify(TURN_RESPONSE));
  };

  try {
    const state = readyState();
    activateState(state, GENERATION, Date.now() - 1);
    await state.storage.put(
      `turn:${GENERATION}:cli`,
      JSON.stringify(TURN_RESPONSE),
    );
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

test("invalid provider data is not cached or reflected to callers", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response("provider secret detail", { status: 401 });

  try {
    const state = readyState();
    const session = new SignalSession(state, turnEnvironment());
    const response = await session.fetch(turnRequest());

    assert.equal(response.status, 502);
    assert.equal(await response.text(), "TURN credential provider failed");
    assert.equal(state.storage.values.has(`turn:${GENERATION}:cli`), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("signaling forwards exact bounded text only to the opposite role", async () => {
  const state = readyState();
  const session = new SignalSession(state, turnEnvironment());
  const cli = state.sockets.cli[0];
  const phone = state.sockets.phone[0];
  const envelope = JSON.stringify({ v: 2, body: "opaque SDP and MAC" });

  await session.webSocketMessage(cli, envelope);
  assert.deepEqual(phone.sent, [envelope]);
  assert.equal(cli.attachment.forwardedMessages, 1);

  await session.webSocketMessage(cli, "x".repeat(128 * 1024 + 1));
  assert.deepEqual(cli.closed.at(-1), [1009, "signal too large"]);
  assert.deepEqual(phone.sent, [envelope]);
});

test("signaling caps the number of frames forwarded by each socket", async () => {
  const state = readyState();
  const session = new SignalSession(state, turnEnvironment());
  const cli = state.sockets.cli[0];
  const phone = state.sockets.phone[0];

  for (let index = 0; index < 8; index += 1) {
    await session.webSocketMessage(cli, `signal-${index}`);
  }
  assert.equal(phone.sent.length, 8);

  await session.webSocketMessage(cli, "signal-8");
  assert.equal(phone.sent.length, 8);
  assert.deepEqual(cli.closed.at(-1), [1008, "too many signals"]);
});

test("session alarm closes peers and erases cached credentials", async () => {
  const state = readyState(GENERATION, Date.now() - 1);
  await state.storage.put(`turn:${GENERATION}:cli`, "credential");
  const session = new SignalSession(state, turnEnvironment());

  await session.alarm();

  assert.equal(state.storage.values.size, 0);
  assert.deepEqual(state.sockets.cli[0].closed, [[1001, "session expired"]]);
  assert.deepEqual(state.sockets.phone[0].closed, [[1001, "session expired"]]);
});

test("a stale alarm cannot erase a newer live generation", async () => {
  const expiresAt = Date.now() + 20 * 60 * 1000;
  const state = readyState("generation-b", expiresAt);
  await state.storage.put("turn:generation-b:cli", "credential");
  state.storage.alarm = null;
  const session = new SignalSession(state, turnEnvironment());

  await session.alarm();

  assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), {
    kind: "active",
    generation: "generation-b",
    expiresAt,
  });
  assert.equal(state.storage.values.get("turn:generation-b:cli"), "credential");
  assert.equal(state.storage.alarm, expiresAt);
  assert.deepEqual(state.sockets.cli[0].closed, []);
  assert.deepEqual(state.sockets.phone[0].closed, []);
});
