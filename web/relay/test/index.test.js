import assert from "node:assert/strict";
import test from "node:test";

import worker, { SignalSession } from "../src/index.js";

const RID = "A".repeat(43);
const ORIGIN = "https://keytap.jul.sh";

class MemoryStorage {
  constructor() {
    this.values = new Map();
    this.alarm = null;
  }

  async get(key) { return this.values.get(key); }
  async put(key, value) { this.values.set(key, value); }
  async deleteAll() { this.values.clear(); }
  async deleteAlarm() { this.alarm = null; }
  async getAlarm() { return this.alarm; }
  async setAlarm(value) { this.alarm = value; }
}

class FakeSocket {
  constructor(role) {
    this.attachment = { kind: "peer", role, forwardedMessages: 0 };
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

function readyState() {
  const state = new FakeState();
  state.sockets.cli.push(new FakeSocket("cli"));
  state.sockets.phone.push(new FakeSocket("phone"));
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
  const state = new FakeState();
  state.sockets.cli.push(new FakeSocket("cli"));
  const session = new SignalSession(state, turnEnvironment());
  const request = new Request(`https://relay.test/v2/signal/${RID}?role=cli`, {
    headers: { Upgrade: "websocket" },
  });

  const response = await session.fetch(request);
  assert.equal(response.status, 409);
  assert.equal(await response.text(), "cli is already connected");
});

test("TURN credentials require both roles to be connected", async () => {
  const state = new FakeState();
  state.sockets.cli.push(new FakeSocket("cli"));
  const session = new SignalSession(state, turnEnvironment());

  const response = await session.fetch(turnRequest());
  assert.equal(response.status, 409);
  assert.equal(await response.text(), "Both peers must be connected");
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
    assert.equal(typeof state.storage.values.get("turn:cli"), "string");
    assert.equal(typeof state.storage.values.get("turn:phone"), "string");
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

test("invalid provider data is not cached or reflected to callers", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () => new Response("provider secret detail", { status: 401 });

  try {
    const state = readyState();
    const session = new SignalSession(state, turnEnvironment());
    const response = await session.fetch(turnRequest());

    assert.equal(response.status, 502);
    assert.equal(await response.text(), "TURN credential provider failed");
    assert.equal(state.storage.values.has("turn:cli"), false);
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
  const state = readyState();
  await state.storage.put("turn:cli", "credential");
  const session = new SignalSession(state, turnEnvironment());

  await session.alarm();

  assert.equal(state.storage.values.size, 0);
  assert.deepEqual(state.sockets.cli[0].closed, [[1001, "session expired"]]);
  assert.deepEqual(state.sockets.phone[0].closed, [[1001, "session expired"]]);
});
