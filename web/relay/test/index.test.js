import assert from "node:assert/strict";
import test from "node:test";

import worker, { RelayRoom } from "../src/index.js";

const ROOM_ID = "A".repeat(43);
const LIFECYCLE_KEY = "room:lifecycle";
const WAITING_MS = 5 * 60 * 1000;
const PAIRED_MS = 8 * 60 * 1000;
const TOMBSTONE_MS = 60 * 60 * 1000;

const NativeResponse = globalThis.Response;
const NativeWebSocketPair = globalThis.WebSocketPair;
const NativeWebSocket = globalThis.WebSocket;

class UpgradeResponse {
  constructor(body, init = {}) {
    if (init.status !== 101) return new NativeResponse(body, init);
    this.status = 101;
    this.headers = new Headers(init.headers);
    this.webSocket = init.webSocket;
  }
}

class FakeSocket {
  constructor() {
    this.attachment = null;
    this.sent = [];
    this.closed = [];
    this.readyState = 1;
  }

  serializeAttachment(value) { this.attachment = structuredClone(value); }
  deserializeAttachment() { return structuredClone(this.attachment); }
  send(value) { this.sent.push(value); }
  close(code, reason) {
    this.closed.push({ code, reason });
    this.readyState = 2;
  }
}

class TestWebSocketPair {
  constructor() {
    this.client = { kind: "client" };
    this.server = new FakeSocket();
  }
}

globalThis.Response = UpgradeResponse;
globalThis.WebSocketPair = TestWebSocketPair;
globalThis.WebSocket = { CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3 };

process.on("exit", () => {
  globalThis.Response = NativeResponse;
  if (NativeWebSocketPair === undefined) delete globalThis.WebSocketPair;
  else globalThis.WebSocketPair = NativeWebSocketPair;
  if (NativeWebSocket === undefined) delete globalThis.WebSocket;
  else globalThis.WebSocket = NativeWebSocket;
});

class MemoryStorage {
  constructor() {
    this.values = new Map();
    this.alarm = null;
  }

  async get(key) { return this.values.get(key); }
  async put(key, value) { this.values.set(key, structuredClone(value)); }
  async setAlarm(value) { this.alarm = value; }
  async deleteAlarm() { this.alarm = null; }
  async deleteAll() { this.values.clear(); }
}

class FakeState {
  constructor() {
    this.storage = new MemoryStorage();
    this.socketsByTag = new Map([["cli", []], ["approver", []]]);
    this.accepted = [];
    this.lifecycleAtAcceptance = [];
  }

  acceptWebSocket(socket, tags) {
    this.accepted.push(socket);
    this.lifecycleAtAcceptance.push(structuredClone(
      this.storage.values.get(LIFECYCLE_KEY),
    ));
    for (const tag of tags) this.socketsByTag.get(tag).push(socket);
  }

  getWebSockets(tag) {
    return tag === undefined
      ? [...this.accepted]
      : [...(this.socketsByTag.get(tag) ?? [])];
  }
}

function request(role, roomId = ROOM_ID, options = {}) {
  return new Request(`https://relay.test/room/${roomId}?role=${role}`, {
    headers: { Upgrade: "websocket" },
    ...options,
  });
}

async function open(room, role) {
  return room.fetch(request(role));
}

async function connectedRoom() {
  const state = new FakeState();
  const room = new RelayRoom(state);
  assert.equal((await open(room, "cli")).status, 101);
  assert.equal((await open(room, "approver")).status, 101);
  return {
    state,
    room,
    cli: state.socketsByTag.get("cli")[0],
    approver: state.socketsByTag.get("approver")[0],
  };
}

function assertDeadline(value, duration, before, after) {
  assert.ok(value >= before + duration);
  assert.ok(value <= after + duration);
}

test("Worker routes only the exact canonical room WebSocket URL", async () => {
  let routed = null;
  let allowUpgrade = true;
  const rateLimitKeys = [];
  const env = {
    ROOM_UPGRADE_RATE_LIMITER: {
      async limit({ key }) {
        rateLimitKeys.push(key);
        return { success: allowUpgrade };
      },
    },
    RELAY_ROOM: {
      getByName(id) {
        routed = id;
        return { fetch: async () => new Response(null, { status: 204 }) };
      },
    },
  };

  assert.equal((await worker.fetch(request("cli"), env)).status, 204);
  assert.equal(routed, ROOM_ID);
  assert.deepEqual(rateLimitKeys, ["unattributed"]);

  for (const url of [
    "https://relay.test/relay/legacy-session",
    `https://relay.test/v2/signal/${ROOM_ID}`,
    `http://relay.test/room/${ROOM_ID}?role=cli`,
    `https://relay.test/room/${ROOM_ID}`,
    `https://relay.test/room/${ROOM_ID}/?role=cli`,
    `https://relay.test/room/${ROOM_ID}?role=phone`,
    `https://relay.test/room/${ROOM_ID}?role=cli&extra=1`,
    `https://relay.test/room/${ROOM_ID}?role=cli&`,
    `https://relay.test/room/${ROOM_ID}?role=%63li`,
    `https://relay.test/room/${"B".repeat(43)}?role=cli`,
  ]) {
    routed = null;
    const response = await worker.fetch(new Request(url, {
      headers: { Upgrade: "websocket" },
    }), env);
    assert.equal(response.status, 404, url);
    assert.equal(routed, null, url);
  }

  routed = null;
  assert.equal((await worker.fetch(new Request(
    `https://relay.test/room/${ROOM_ID}?role=cli`,
  ), env)).status, 426);
  assert.equal(routed, null);

  allowUpgrade = false;
  const limited = request("cli", ROOM_ID, {
    headers: {
      Upgrade: "websocket",
      "CF-Connecting-IP": "192.0.2.1",
    },
  });
  assert.equal((await worker.fetch(limited, env)).status, 429);
  assert.equal(routed, null);
  assert.equal(rateLimitKeys.at(-1), "192.0.2.1");
});

test("CLI waits five minutes and the first approver pairs the room for eight", async () => {
  const state = new FakeState();
  const room = new RelayRoom(state);
  const beforeWaiting = Date.now();
  assert.equal((await open(room, "cli")).status, 101);
  const afterWaiting = Date.now();

  const waiting = structuredClone(state.storage.values.get(LIFECYCLE_KEY));
  assert.deepEqual(Object.keys(waiting).sort(), ["expiresAt", "kind"]);
  assert.equal(waiting.kind, "waiting");
  assertDeadline(waiting.expiresAt, WAITING_MS, beforeWaiting, afterWaiting);
  assert.equal(state.storage.alarm, waiting.expiresAt);
  assert.equal(state.lifecycleAtAcceptance[0].kind, "waiting");
  assert.deepEqual(state.socketsByTag.get("cli")[0].attachment, {
    kind: "peer",
    role: "cli",
    sent: 0,
  });

  assert.equal((await open(room, "cli")).status, 409);
  assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), waiting);

  const beforePaired = Date.now();
  assert.equal((await open(room, "approver")).status, 101);
  const afterPaired = Date.now();
  const paired = structuredClone(state.storage.values.get(LIFECYCLE_KEY));
  assert.equal(paired.kind, "paired");
  assertDeadline(paired.expiresAt, PAIRED_MS, beforePaired, afterPaired);
  assert.equal(state.storage.alarm, paired.expiresAt);
  assert.equal(state.lifecycleAtAcceptance[1].kind, "paired");

  assert.equal((await open(room, "approver")).status, 409);
  assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), paired);
  assert.equal(state.storage.alarm, paired.expiresAt);
  assert.equal(state.accepted.length, 2);

  state.socketsByTag.get("approver")[0].readyState = WebSocket.CLOSED;
  assert.equal((await open(new RelayRoom(state), "approver")).status, 409);
  assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), paired);
  assert.equal(state.accepted.length, 2);
});

test("parallel upgrades admit exactly one socket per role", async () => {
  const state = new FakeState();
  const room = new RelayRoom(state);
  const cli = await Promise.all(Array.from({ length: 4 }, () => open(room, "cli")));
  assert.deepEqual(cli.map(({ status }) => status).sort(), [101, 409, 409, 409]);
  assert.equal(state.socketsByTag.get("cli").length, 1);

  const approver = await Promise.all(
    Array.from({ length: 4 }, () => open(room, "approver")),
  );
  assert.deepEqual(
    approver.map(({ status }) => status).sort(),
    [101, 409, 409, 409],
  );
  assert.equal(state.socketsByTag.get("approver").length, 1);
  assert.equal(state.accepted.length, 2);
  assert.equal(state.storage.values.get(LIFECYCLE_KEY).kind, "paired");
});

test("approver cannot create a room or join without a live CLI", async () => {
  const missingState = new FakeState();
  assert.equal((await open(new RelayRoom(missingState), "approver")).status, 410);
  assert.equal(missingState.storage.values.has(LIFECYCLE_KEY), false);

  const state = new FakeState();
  const room = new RelayRoom(state);
  await open(room, "cli");
  state.socketsByTag.get("cli")[0].readyState = WebSocket.CLOSED;
  const before = Date.now();
  assert.equal((await open(room, "approver")).status, 410);
  const after = Date.now();
  const lifecycle = state.storage.values.get(LIFECYCLE_KEY);
  assert.equal(lifecycle.kind, "closed");
  assertDeadline(lifecycle.expiresAt, TOMBSTONE_MS, before, after);
});

test("binary frames are forwarded opaquely across hibernation", async () => {
  const { state, room, cli, approver } = await connectedRoom();
  const fromCli = Uint8Array.from([0, 1, 2, 255]).buffer;
  await room.webSocketMessage(cli, fromCli);
  assert.strictEqual(approver.sent[0], fromCli);
  assert.deepEqual(cli.attachment, { kind: "peer", role: "cli", sent: 1 });

  const resumed = new RelayRoom(state);
  const fromApprover = Uint8Array.from([9, 8, 7]).buffer;
  await resumed.webSocketMessage(approver, fromApprover);
  assert.strictEqual(cli.sent[0], fromApprover);
  assert.deepEqual(approver.attachment, {
    kind: "peer",
    role: "approver",
    sent: 1,
  });
});

test("only binary frames of at most 16 KiB are accepted", async () => {
  const { state, room, cli, approver } = await connectedRoom();
  await room.webSocketMessage(cli, new ArrayBuffer(16 * 1024));
  assert.equal(approver.sent.length, 1);

  const before = Date.now();
  await room.webSocketMessage(cli, new ArrayBuffer(16 * 1024 + 1));
  const after = Date.now();
  const lifecycle = state.storage.values.get(LIFECYCLE_KEY);
  assert.equal(lifecycle.kind, "closed");
  assertDeadline(lifecycle.expiresAt, TOMBSTONE_MS, before, after);
  assert.equal(cli.closed.at(-1).code, 1009);
  assert.equal(approver.closed.at(-1).code, 1009);

  const textRoom = await connectedRoom();
  await textRoom.room.webSocketMessage(textRoom.cli, "ciphertext");
  assert.equal(textRoom.state.storage.values.get(LIFECYCLE_KEY).kind, "closed");
  assert.equal(textRoom.cli.closed.at(-1).code, 1008);
});

test("the ninth frame from either role closes the room", async () => {
  const { state, room, cli, approver } = await connectedRoom();
  for (let index = 0; index < 8; index += 1) {
    await room.webSocketMessage(cli, new ArrayBuffer(1));
  }
  assert.equal(approver.sent.length, 8);
  assert.deepEqual(cli.attachment, { kind: "peer", role: "cli", sent: 8 });

  await room.webSocketMessage(cli, new ArrayBuffer(1));
  assert.equal(approver.sent.length, 8);
  assert.equal(state.storage.values.get(LIFECYCLE_KEY).kind, "closed");
  assert.equal(cli.closed.at(-1).code, 1008);
});

test("peer close and error produce one durable, non-extending tombstone", async () => {
  const { state, room, cli, approver } = await connectedRoom();
  await room.webSocketClose(cli, 1000, "done", true);
  const first = structuredClone(state.storage.values.get(LIFECYCLE_KEY));
  assert.equal(first.kind, "closed");
  assert.equal(approver.closed.at(-1).reason, "peer left");

  await room.webSocketError(approver, new Error("network"));
  assert.deepEqual(state.storage.values.get(LIFECYCLE_KEY), first);
  assert.equal(state.storage.alarm, first.expiresAt);
});

test("waiting and paired expiry close rooms, then tombstones are erased", async () => {
  const waitingState = new FakeState();
  const waitingRoom = new RelayRoom(waitingState);
  await open(waitingRoom, "cli");
  const waitingCli = waitingState.socketsByTag.get("cli")[0];
  waitingState.storage.values.set(LIFECYCLE_KEY, {
    kind: "waiting",
    expiresAt: Date.now() - 1,
  });
  await waitingRoom.alarm();
  assert.equal(waitingState.storage.values.get(LIFECYCLE_KEY).kind, "closed");
  assert.equal(waitingCli.closed.at(-1).reason, "room expired");

  const { state, room, cli, approver } = await connectedRoom();
  state.storage.values.set(LIFECYCLE_KEY, {
    kind: "paired",
    expiresAt: Date.now() - 1,
  });

  const before = Date.now();
  await room.alarm();
  const after = Date.now();
  const closed = state.storage.values.get(LIFECYCLE_KEY);
  assert.equal(closed.kind, "closed");
  assertDeadline(closed.expiresAt, TOMBSTONE_MS, before, after);
  assert.equal(cli.closed.at(-1).reason, "room expired");
  assert.equal(approver.closed.at(-1).reason, "room expired");

  state.storage.values.set(LIFECYCLE_KEY, {
    kind: "closed",
    expiresAt: Date.now() - 1,
  });
  state.storage.alarm = Date.now() - 1;
  await room.alarm();
  assert.equal(state.storage.values.size, 0);
  assert.equal(state.storage.alarm, null);
});

test("malformed durable state fails closed", async () => {
  const state = new FakeState();
  state.storage.values.set(LIFECYCLE_KEY, {
    kind: "bogus",
    expiresAt: Date.now() + WAITING_MS,
    extra: true,
  });
  const response = await open(new RelayRoom(state), "cli");
  assert.equal(response.status, 410);
  assert.deepEqual(Object.keys(state.storage.values.get(LIFECYCLE_KEY)).sort(), [
    "expiresAt",
    "kind",
  ]);
  assert.equal(state.storage.values.get(LIFECYCLE_KEY).kind, "closed");
});
