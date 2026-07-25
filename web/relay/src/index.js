const CORS_ORIGINS = new Set([
  "https://keytap.jul.sh",
]);

const RENDEZVOUS_ID_PATTERN = "[a-zA-Z0-9_-]{43}";
// Covers the CLI's five-minute scan wait plus its optional ten-minute
// remember window. The room deadline is independent of credential expiry.
const SIGNAL_SESSION_TTL_MS = 20 * 60 * 1000;
const TURN_CREDENTIAL_TTL_SECONDS = 1200;
const MAX_SIGNAL_BYTES = 128 * 1024;
const MAX_SIGNAL_MESSAGES_PER_SOCKET = 8;
const TURN_PROVIDER_RESPONSE_MAX_BYTES = 64 * 1024;
const SIGNAL_LIFECYCLE_KEY = "signal:lifecycle";

/** @typedef {"cli" | "phone"} SignalRole */

/**
 * @typedef {
 *   | { kind: "empty" }
 *   | { kind: "waiting-for-cli", phone: WebSocket }
 *   | { kind: "waiting-for-phone", cli: WebSocket }
 *   | { kind: "ready", cli: WebSocket, phone: WebSocket }
 * } ConnectedPeers
 */

/**
 * @typedef {
 *   | { kind: "missing" }
 *   | { kind: "configured", keyId: string, apiToken: string }
 * } TurnConfiguration
 */

/**
 * @typedef {
 *   | { kind: "missing" }
 *   | { kind: "invalid" }
 *   | { kind: "active", generation: string, expiresAt: number }
 * } SignalLifecycle
 */

/**
 * @typedef {
 *   | { kind: "stored", serialized: string }
 *   | { kind: "expired" }
 * } TurnCredentialMint
 */

/**
 * @param {Request} request
 * @returns {HeadersInit}
 */
function corsHeaders(request) {
  const origin = request.headers.get("Origin") || "";
  const allowed = CORS_ORIGINS.has(origin) ? origin : "";
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "GET, PUT, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
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
    case "phone":
      return value;
    default:
      return null;
  }
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
    value &&
    typeof value === "object" &&
    "kind" in value &&
    value.kind === "active" &&
    "generation" in value &&
    typeof value.generation === "string" &&
    value.generation.length > 0 &&
    "expiresAt" in value &&
    Number.isSafeInteger(value.expiresAt) &&
    value.expiresAt > 0
  ) {
    return {
      kind: "active",
      generation: value.generation,
      expiresAt: value.expiresAt,
    };
  }
  return { kind: "invalid" };
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
 * @param {Request} request
 * @param {number} status
 * @param {string} message
 * @param {HeadersInit} [extraHeaders]
 * @returns {Response}
 */
function v2Error(request, status, message, extraHeaders = {}) {
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
 * Rate-limit only the new public rendezvous surface. Legacy behavior remains
 * unchanged. Cloudflare supplies CF-Connecting-IP at the edge.
 * @param {Request} request
 * @param {any} env
 * @returns {Promise<Response | null>}
 */
async function enforceV2RateLimit(request, env) {
  if (!env.SIGNAL_RATE_LIMIT || typeof env.SIGNAL_RATE_LIMIT.limit !== "function") {
    return v2Error(request, 503, "Rate limiter is not configured");
  }

  const source = request.headers.get("CF-Connecting-IP") || "missing-ip";
  try {
    const result = await env.SIGNAL_RATE_LIMIT.limit({ key: `signal:${source}` });
    if (result.success) {
      return null;
    }
  } catch {
    return v2Error(request, 503, "Rate limiter unavailable");
  }

  return v2Error(request, 429, "Too many requests", { "Retry-After": "60" });
}

export default {
  /**
   * @param {Request} request
   * @param {{ RELAY_SESSION: DurableObjectNamespace, SIGNAL_SESSION: DurableObjectNamespace, SIGNAL_RATE_LIMIT: { limit(input: { key: string }): Promise<{ success: boolean }> } }} env
   * @returns {Promise<Response>}
   */
  async fetch(request, env) {
    const url = new URL(request.url);
    const legacyMatch = url.pathname.match(/^\/relay\/([a-zA-Z0-9_-]{8,44})$/);

    if (legacyMatch) {
      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: corsHeaders(request) });
      }

      const sessionId = legacyMatch[1];
      const id = env.RELAY_SESSION.idFromName(sessionId);
      const stub = env.RELAY_SESSION.get(id);
      return stub.fetch(request);
    }

    const turnMatch = url.pathname.match(
      new RegExp(`^/v2/signal/(${RENDEZVOUS_ID_PATTERN})/turn/(cli|phone)$`),
    );
    const signalMatch = url.pathname.match(
      new RegExp(`^/v2/signal/(${RENDEZVOUS_ID_PATTERN})$`),
    );

    if (!turnMatch && !signalMatch) {
      return new Response("Not found", { status: 404 });
    }

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    const rateLimitResponse = await enforceV2RateLimit(request, env);
    if (rateLimitResponse) {
      return rateLimitResponse;
    }

    const rendezvousId = (turnMatch || signalMatch)[1];
    const id = env.SIGNAL_SESSION.idFromName(rendezvousId);
    const stub = env.SIGNAL_SESSION.get(id);
    return stub.fetch(request);
  },
};

// Sessions are one-time and short-lived: the CLI gives up after 5 minutes,
// so anything older is garbage. The alarm wipes storage after this window.
const SESSION_TTL_MS = 10 * 60 * 1000;

export class RelaySession {
  /**
   * @param {DurableObjectState} state
   * @param {unknown} _env
   */
  constructor(state, _env) {
    this.state = state;
  }

  /**
   * @param {Request} request
   * @returns {Promise<Response>}
   */
  async fetch(request) {
    // WebSocket upgrade (CLI connects here)
    if (request.headers.get("Upgrade") === "websocket") {
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.state.acceptWebSocket(server);
      return new Response(null, { status: 101, webSocket: client });
    }

    // PUT config from CLI
    if (request.method === "PUT") {
      const cors = corsHeaders(request);
      const body = await request.text();

      try {
        JSON.parse(body);
      } catch {
        return new Response("Invalid JSON", { status: 400, headers: cors });
      }

      // Durable storage, not an instance field: with hibernatable WebSockets
      // the runtime evicts this object from memory between events, so
      // in-memory state does not survive until the phone's GET.
      await this.state.storage.put("config", body);
      await this.state.storage.setAlarm(Date.now() + SESSION_TTL_MS);
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    // GET config (phone fetches it)
    if (request.method === "GET") {
      const cors = corsHeaders(request);
      const config = await this.state.storage.get("config");
      if (!config) {
        return new Response("No config", { status: 404, headers: cors });
      }
      return new Response(config, {
        status: 200,
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    // POST from phone with encrypted blob
    if (request.method === "POST") {
      const cors = corsHeaders(request);
      const body = await request.text();

      try {
        JSON.parse(body);
      } catch {
        return new Response("Invalid JSON", { status: 400, headers: cors });
      }

      // Push to all connected WebSockets (should be exactly one: the CLI).
      // The socket stays open afterwards: the page may follow up (a
      // remember opt-in, or a "done" that releases the CLI early), and the
      // CLI closes from its side when it exits.
      let delivered = false;
      for (const ws of this.state.getWebSockets()) {
        try {
          ws.send(body);
          delivered = true;
        } catch {
          // WebSocket already closed
        }
      }

      if (!delivered) {
        return new Response("No CLI connected", { status: 410, headers: cors });
      }

      // The config is one-time; after first delivery nobody refetches it.
      await this.state.storage.deleteAll();
      await this.state.storage.deleteAlarm();

      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { ...cors, "Content-Type": "application/json" },
      });
    }

    return new Response("Method not allowed", {
      status: 405,
      headers: corsHeaders(request),
    });
  }

  async alarm() {
    await this.state.storage.deleteAll();
  }

  async webSocketMessage() {}

  /** @param {WebSocket} ws */
  async webSocketClose(ws) {
    try { ws.close(); } catch {}
  }

  /** @param {WebSocket} ws */
  async webSocketError(ws) {
    try { ws.close(1011, "error"); } catch {}
  }
}

/**
 * A short-lived, single-use WebRTC signaling room. SDP is forwarded as an
 * opaque, bounded string: authentication belongs to the Q-derived protocol at
 * the endpoints, not to this relay.
 */
export class SignalSession {
  /**
   * @param {DurableObjectState} state
   * @param {unknown} env
   */
  constructor(state, env) {
    this.state = state;
    this.env = env;
    /** @type {Map<string, Promise<TurnCredentialMint>>} */
    this.turnCredentialRequests = new Map();
  }

  /**
   * @param {Request} request
   * @returns {Promise<Response>}
   */
  async fetch(request) {
    const url = new URL(request.url);
    const turnMatch = url.pathname.match(
      new RegExp(`^/v2/signal/${RENDEZVOUS_ID_PATTERN}/turn/(cli|phone)$`),
    );

    if (turnMatch) {
      const role = parseSignalRole(turnMatch[1]);
      if (request.method !== "GET") {
        return v2Error(request, 405, "Method not allowed", { Allow: "GET" });
      }
      // The route regex and parser intentionally form a parse boundary.
      if (role === null) {
        return v2Error(request, 400, "Invalid role");
      }
      return this.fetchTurnCredential(request, role);
    }

    if (!url.pathname.match(new RegExp(`^/v2/signal/${RENDEZVOUS_ID_PATTERN}$`))) {
      return v2Error(request, 404, "Not found");
    }

    if (request.method !== "GET" || request.headers.get("Upgrade") !== "websocket") {
      return v2Error(request, 426, "WebSocket upgrade required", {
        Upgrade: "websocket",
      });
    }

    const role = parseSignalRole(url.searchParams.get("role"));
    if (role === null) {
      return v2Error(request, 400, "role must be cli or phone");
    }

    const lifecycle = await this.beginOrJoinSignalSession();
    switch (lifecycle.kind) {
      case "expired":
        return v2Error(request, 410, "Signal session expired");
      case "active":
        break;
    }

    if (this.socketsForRole(role, lifecycle.generation).length !== 0) {
      return v2Error(request, 409, `${role} is already connected`);
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.serializeAttachment({
      kind: "peer",
      role,
      generation: lifecycle.generation,
      forwardedMessages: 0,
    });
    this.state.acceptWebSocket(server, [role]);
    this.notifyPeerReady(lifecycle.generation);

    return new Response(null, { status: 101, webSocket: client });
  }

  /**
   * @param {SignalRole} role
   * @param {string} generation
   * @returns {WebSocket[]}
   */
  socketsForRole(role, generation) {
    return this.state.getWebSockets(role).filter((socket) => {
      const attachment = socket.deserializeAttachment();
      return (
        attachment &&
        attachment.kind === "peer" &&
        attachment.role === role &&
        attachment.generation === generation
      );
    });
  }

  /**
   * @param {string} generation
   * @returns {ConnectedPeers}
   */
  connectedPeers(generation) {
    const cli = this.socketsForRole("cli", generation);
    const phone = this.socketsForRole("phone", generation);

    if (cli.length === 1 && phone.length === 1) {
      return { kind: "ready", cli: cli[0], phone: phone[0] };
    }
    if (cli.length === 1) {
      return { kind: "waiting-for-phone", cli: cli[0] };
    }
    if (phone.length === 1) {
      return { kind: "waiting-for-cli", phone: phone[0] };
    }
    return { kind: "empty" };
  }

  /** @param {string} generation */
  notifyPeerReady(generation) {
    const peers = this.connectedPeers(generation);
    switch (peers.kind) {
      case "ready": {
        const message = JSON.stringify({ type: "peer-ready" });
        try { peers.cli.send(message); } catch {}
        try { peers.phone.send(message); } catch {}
        return;
      }
      case "empty":
      case "waiting-for-cli":
      case "waiting-for-phone":
        return;
    }
  }

  /**
   * Create a generation only while admitting a WebSocket. TURN requests never
   * create sessions, so an alarmed room cannot be revived by a stale request.
   * @returns {Promise<
   *   | { kind: "active", generation: string, expiresAt: number }
   *   | { kind: "expired" }
   * >}
   */
  async beginOrJoinSignalSession() {
    const lifecycle = parseSignalLifecycle(
      await this.state.storage.get(SIGNAL_LIFECYCLE_KEY),
    );
    switch (lifecycle.kind) {
      case "active":
        if (lifecycle.expiresAt <= Date.now()) {
          await this.expireSignalSession();
          return { kind: "expired" };
        }
        await this.ensureLifecycleAlarm(lifecycle.expiresAt);
        return lifecycle;
      case "invalid":
        await this.expireSignalSession();
        return { kind: "expired" };
      case "missing": {
        const active = {
          kind: "active",
          generation: crypto.randomUUID(),
          expiresAt: Date.now() + SIGNAL_SESSION_TTL_MS,
        };
        await this.state.storage.put(SIGNAL_LIFECYCLE_KEY, active);
        await this.ensureLifecycleAlarm(active.expiresAt);
        return active;
      }
    }
  }

  /**
   * @returns {Promise<
   *   | { kind: "active", generation: string, expiresAt: number }
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
   * @param {SignalRole} role
   * @returns {Promise<Response>}
   */
  async fetchTurnCredential(request, role) {
    const lifecycle = await this.requireActiveSignalSession();
    switch (lifecycle.kind) {
      case "expired":
        return v2Error(request, 410, "Signal session expired");
      case "active":
        break;
    }

    const peers = this.connectedPeers(lifecycle.generation);
    switch (peers.kind) {
      case "empty":
      case "waiting-for-cli":
      case "waiting-for-phone":
        return v2Error(request, 409, "Both peers must be connected");
      case "ready":
        break;
    }

    const config = turnConfiguration(this.env);
    switch (config.kind) {
      case "missing":
        return v2Error(request, 503, "TURN is not configured");
      case "configured":
        break;
    }

    const storageKey = `turn:${lifecycle.generation}:${role}`;
    const cached = await this.state.storage.get(storageKey);
    if (typeof cached === "string") {
      return this.turnCredentialResponse(request, cached);
    }

    const requestKey = `${lifecycle.generation}:${role}`;
    let pending = this.turnCredentialRequests.get(requestKey);
    if (!pending) {
      pending = this.mintAndStoreTurnCredential(
        storageKey,
        lifecycle.generation,
        config,
      );
      this.turnCredentialRequests.set(requestKey, pending);
    }

    try {
      const result = await pending;
      switch (result.kind) {
        case "stored":
          return this.turnCredentialResponse(request, result.serialized);
        case "expired":
          return v2Error(request, 410, "Signal session expired");
      }
    } catch {
      return v2Error(request, 502, "TURN credential provider failed");
    } finally {
      if (this.turnCredentialRequests.get(requestKey) === pending) {
        this.turnCredentialRequests.delete(requestKey);
      }
    }
  }

  /**
   * @param {string} storageKey
   * @param {string} generation
   * @param {{ kind: "configured", keyId: string, apiToken: string }} config
   * @returns {Promise<TurnCredentialMint>}
   */
  async mintAndStoreTurnCredential(storageKey, generation, config) {
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

    let parsed;
    try {
      parsed = JSON.parse(body);
    } catch {
      throw new Error("TURN provider returned invalid JSON");
    }
    if (!isTurnCredentialResponse(parsed)) {
      throw new Error("TURN provider returned an invalid credential set");
    }

    const serialized = JSON.stringify(parsed);
    if (this.connectedPeers(generation).kind !== "ready") {
      return { kind: "expired" };
    }

    /** @type {TurnCredentialMint} */
    const result = await this.state.storage.transaction(async (transaction) => {
      const lifecycle = parseSignalLifecycle(
        await transaction.get(SIGNAL_LIFECYCLE_KEY),
      );
      switch (lifecycle.kind) {
        case "missing":
        case "invalid":
          return { kind: "expired" };
        case "active":
          if (
            lifecycle.generation !== generation ||
            lifecycle.expiresAt <= Date.now()
          ) {
            return { kind: "expired" };
          }
          await transaction.put(storageKey, serialized);
          return { kind: "stored", serialized };
      }
    });
    return result;
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
      typeof attachment.generation !== "string" ||
      attachment.generation.length === 0 ||
      !Number.isSafeInteger(attachment.forwardedMessages) ||
      attachment.forwardedMessages < 0
    ) {
      try { ws.close(1008, "invalid peer state"); } catch {}
      return;
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
      case "active":
        if (lifecycle.generation !== attachment.generation) {
          try { ws.close(1008, "stale signal session"); } catch {}
          return;
        }
        break;
    }

    /** @type {SignalRole} */
    const role = attachment.role;
    /** @type {SignalRole} */
    const destinationRole = role === "cli" ? "phone" : "cli";
    const destinations = this.socketsForRole(destinationRole, lifecycle.generation);
    if (destinations.length !== 1) {
      try { ws.send(JSON.stringify({ type: "peer-not-ready" })); } catch {}
      return;
    }

    ws.serializeAttachment({
      kind: "peer",
      role,
      generation: lifecycle.generation,
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
        if (lifecycle.expiresAt > Date.now()) {
          // Alarm delivery is at-least-once. A retry for an erased generation
          // must not delete a newer session using the same Durable Object ID.
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
    // This Worker's compatibility date predates deleteAll() clearing alarms.
    await this.state.storage.deleteAlarm();
  }

  /** @param {WebSocket} ws */
  async webSocketClose(ws) {
    this.notifyOtherPeerLeft(ws);
    try { ws.close(); } catch {}
  }

  /** @param {WebSocket} ws */
  async webSocketError(ws) {
    this.notifyOtherPeerLeft(ws);
    try { ws.close(1011, "error"); } catch {}
  }

  /** @param {WebSocket} ws */
  notifyOtherPeerLeft(ws) {
    const attachment = ws.deserializeAttachment();
    const role = parseSignalRole(attachment?.role ?? null);
    if (role === null) {
      return;
    }
    if (typeof attachment.generation !== "string" || attachment.generation.length === 0) {
      return;
    }
    const destinationRole = role === "cli" ? "phone" : "cli";
    for (const peer of this.socketsForRole(destinationRole, attachment.generation)) {
      try { peer.send(JSON.stringify({ type: "peer-left" })); } catch {}
    }
  }
}

/**
 * Validate only the provider boundary. The returned JSON is otherwise passed
 * through unchanged so browser and native clients receive Cloudflare's normal
 * RTCIceServer shape.
 * @param {unknown} value
 * @returns {boolean}
 */
function isTurnCredentialResponse(value) {
  if (!value || typeof value !== "object" || !("iceServers" in value)) {
    return false;
  }
  if (!Array.isArray(value.iceServers) || value.iceServers.length === 0) {
    return false;
  }

  let foundAuthenticatedTurnServer = false;
  for (const server of value.iceServers) {
    if (!server || typeof server !== "object" || !("urls" in server)) {
      return false;
    }
    const urls = typeof server.urls === "string" ? [server.urls] : server.urls;
    if (!Array.isArray(urls) || urls.length === 0 || urls.some((url) => typeof url !== "string")) {
      return false;
    }

    if (urls.some((url) => url.startsWith("turn:") || url.startsWith("turns:"))) {
      if (typeof server.username !== "string" || typeof server.credential !== "string") {
        return false;
      }
      foundAuthenticatedTurnServer = true;
    }
  }
  return foundAuthenticatedTurnServer;
}
