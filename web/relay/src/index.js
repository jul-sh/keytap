const ROOM_PATH = /^\/room\/([A-Za-z0-9_-]{43})$/;
const LIFECYCLE_KEY = "room:lifecycle";
const WAITING_MS = 5 * 60 * 1000;
const PAIRED_MS = 8 * 60 * 1000;
const TOMBSTONE_MS = 60 * 60 * 1000;
const MAX_FRAME_BYTES = 16 * 1024;
const MAX_FRAMES_PER_ROLE = 8;

/** @typedef {"cli" | "approver"} Role */

/**
 * @typedef {
 *   | { kind: "missing" }
 *   | { kind: "invalid" }
 *   | { kind: "waiting", expiresAt: number }
 *   | { kind: "paired", expiresAt: number }
 *   | { kind: "closed", expiresAt: number }
 * } Lifecycle
 */

/**
 * @typedef {{ kind: "peer", role: Role, sent: number }} Peer
 */

function canonicalRoomId(value) {
  try {
    const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=";
    const binary = atob(padded);
    const canonical = btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");
    return binary.length === 32 && canonical === value;
  } catch {
    return false;
  }
}

function parseRoom(request) {
  const url = new URL(request.url);
  const match = ROOM_PATH.exec(url.pathname);
  const role = url.search === "?role=cli"
    ? "cli"
    : url.search === "?role=approver" ? "approver" : null;
  if (
    url.protocol !== "https:" ||
    !match ||
    !canonicalRoomId(match[1]) ||
    !role
  ) {
    return null;
  }
  return { id: match[1], role };
}

/** @returns {Lifecycle} */
function parseLifecycle(value) {
  if (value === undefined) return { kind: "missing" };
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !== "expiresAt,kind" ||
    !["waiting", "paired", "closed"].includes(value.kind) ||
    !Number.isSafeInteger(value.expiresAt) ||
    value.expiresAt <= 0
  ) {
    return { kind: "invalid" };
  }
  return { kind: value.kind, expiresAt: value.expiresAt };
}

/** @returns {Peer | null} */
function parsePeer(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !== "kind,role,sent" ||
    value.kind !== "peer" ||
    (value.role !== "cli" && value.role !== "approver") ||
    !Number.isSafeInteger(value.sent) ||
    value.sent < 0 ||
    value.sent > MAX_FRAMES_PER_ROLE
  ) {
    return null;
  }
  return value;
}

function error(status, message) {
  return new Response(message, { status });
}

export default {
  async fetch(request, env) {
    const room = parseRoom(request);
    if (!room) return error(404, "Not found");
    if (
      request.method !== "GET" ||
      request.headers.get("Upgrade")?.toLowerCase() !== "websocket"
    ) {
      return error(426, "WebSocket upgrade required");
    }
    const { success } = await env.ROOM_UPGRADE_RATE_LIMITER.limit({
      key: request.headers.get("CF-Connecting-IP") || "unattributed",
    });
    if (!success) return error(429, "Too many room attempts");
    return env.RELAY_ROOM.getByName(room.id).fetch(request);
  },
};

export class RelayRoom {
  constructor(state) {
    this.state = state;
    this.admissions = Promise.resolve();
  }

  async fetch(request) {
    const room = parseRoom(request);
    if (!room) return error(404, "Not found");
    if (
      request.method !== "GET" ||
      request.headers.get("Upgrade")?.toLowerCase() !== "websocket"
    ) {
      return error(426, "WebSocket upgrade required");
    }

    return this.serializeAdmission(async () => {
      const admission = await this.admit(room.role);
      if (admission === "closed") return error(410, "Room closed");
      if (admission === "duplicate") {
        return error(409, `${room.role} already connected`);
      }

      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.state.acceptWebSocket(server, [room.role]);
      server.serializeAttachment({ kind: "peer", role: room.role, sent: 0 });
      return new Response(null, { status: 101, webSocket: client });
    });
  }

  serializeAdmission(operation) {
    const result = this.admissions.then(operation);
    this.admissions = result.catch(() => {});
    return result;
  }

  /** @param {Role} role */
  async admit(role) {
    const lifecycle = parseLifecycle(await this.state.storage.get(LIFECYCLE_KEY));
    switch (lifecycle.kind) {
      case "missing":
        if (role === "approver") return "closed";
        await this.persist({ kind: "waiting", expiresAt: Date.now() + WAITING_MS });
        return "accepted";
      case "invalid":
        await this.closeRoom(1011, "invalid room state");
        return "closed";
      case "closed":
        if (lifecycle.expiresAt <= Date.now()) await this.cleanup();
        return "closed";
      case "waiting":
        if (lifecycle.expiresAt <= Date.now()) {
          await this.closeRoom(1001, "room expired");
          return "closed";
        }
        if (role === "cli") return "duplicate";
        if (
          this.sockets("cli").length !== 1 ||
          this.sockets("approver").length !== 0
        ) {
          await this.closeRoom(1001, "CLI left");
          return "closed";
        }
        await this.persist({ kind: "paired", expiresAt: Date.now() + PAIRED_MS });
        return "accepted";
      case "paired":
        if (lifecycle.expiresAt <= Date.now()) {
          await this.closeRoom(1001, "room expired");
          return "closed";
        }
        return "duplicate";
    }
  }

  async persist(lifecycle) {
    await Promise.all([
      this.state.storage.put(LIFECYCLE_KEY, lifecycle),
      this.state.storage.setAlarm(lifecycle.expiresAt),
    ]);
  }

  /** @param {Role} role */
  sockets(role) {
    return this.state.getWebSockets(role).filter((socket) =>
      socket.readyState === WebSocket.OPEN && parsePeer(socket.deserializeAttachment())?.role === role
    );
  }

  async requireOpen() {
    const lifecycle = parseLifecycle(await this.state.storage.get(LIFECYCLE_KEY));
    if (
      (lifecycle.kind === "waiting" || lifecycle.kind === "paired") &&
      lifecycle.expiresAt > Date.now()
    ) return true;
    if (lifecycle.kind === "waiting" || lifecycle.kind === "paired") {
      await this.closeRoom(1001, "room expired");
    }
    else if (lifecycle.kind === "invalid") await this.closeRoom(1011, "invalid room state");
    return false;
  }

  async webSocketMessage(socket, message) {
    if (!(message instanceof ArrayBuffer)) {
      await this.closeRoom(1008, "binary frames required");
      return;
    }
    if (message.byteLength > MAX_FRAME_BYTES) {
      await this.closeRoom(1009, "frame too large");
      return;
    }

    const peer = parsePeer(socket.deserializeAttachment());
    if (!peer || !(await this.requireOpen())) {
      if (!peer) await this.closeRoom(1008, "invalid peer state");
      return;
    }
    if (peer.sent >= MAX_FRAMES_PER_ROLE) {
      await this.closeRoom(1008, "frame limit reached");
      return;
    }

    const destination = peer.role === "cli" ? "approver" : "cli";
    const sockets = this.sockets(destination);
    if (sockets.length !== 1) {
      await this.closeRoom(1001, "peer left");
      return;
    }

    try {
      sockets[0].send(message);
      socket.serializeAttachment({ ...peer, sent: peer.sent + 1 });
    } catch {
      await this.closeRoom(1011, "relay failed");
    }
  }

  async closeRoom(code, reason) {
    const lifecycle = parseLifecycle(await this.state.storage.get(LIFECYCLE_KEY));
    switch (lifecycle.kind) {
      case "missing":
        break;
      case "waiting":
      case "paired":
      case "invalid":
        await this.persist({ kind: "closed", expiresAt: Date.now() + TOMBSTONE_MS });
        break;
      case "closed":
        if (lifecycle.expiresAt <= Date.now()) {
          await this.cleanup();
          return;
        }
        await this.state.storage.setAlarm(lifecycle.expiresAt);
        break;
    }
    for (const socket of this.state.getWebSockets()) {
      try { socket.close(code, reason); } catch {}
    }
  }

  async webSocketClose() {
    await this.closeRoom(1000, "peer left");
  }

  async webSocketError() {
    await this.closeRoom(1011, "peer error");
  }

  async alarm() {
    const lifecycle = parseLifecycle(await this.state.storage.get(LIFECYCLE_KEY));
    switch (lifecycle.kind) {
      case "waiting":
      case "paired":
        if (lifecycle.expiresAt <= Date.now()) {
          await this.closeRoom(1001, "room expired");
        } else {
          await this.state.storage.setAlarm(lifecycle.expiresAt);
        }
        return;
      case "closed":
        if (lifecycle.expiresAt <= Date.now()) {
          await this.cleanup();
        } else {
          await this.state.storage.setAlarm(lifecycle.expiresAt);
        }
        return;
      case "invalid":
        await this.closeRoom(1011, "invalid room state");
        return;
      case "missing":
        await this.cleanup();
    }
  }

  async cleanup() {
    for (const socket of this.state.getWebSockets()) {
      try { socket.close(1001, "room expired"); } catch {}
    }
    await Promise.all([
      this.state.storage.deleteAll(),
      this.state.storage.deleteAlarm(),
    ]);
  }
}
