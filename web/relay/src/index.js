const CORS_ORIGINS = new Set([
  "https://keytap.jul.sh",
]);

const RENDEZVOUS_ID_PATTERN = "[a-zA-Z0-9_-]{43}";
// Covers the CLI's five-minute scan wait plus its optional ten-minute
// remember window without outliving Cloudflare's 20-minute credential.
const SIGNAL_SESSION_TTL_MS = 20 * 60 * 1000;
const TURN_CREDENTIAL_TTL_SECONDS = 1200;
const MAX_SIGNAL_BYTES = 128 * 1024;
const MAX_SIGNAL_MESSAGES_PER_SOCKET = 8;
const TURN_PROVIDER_RESPONSE_MAX_BYTES = 64 * 1024;

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
    /** @type {Map<SignalRole, Promise<string>>} */
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

    if (this.state.getWebSockets(role).length !== 0) {
      return v2Error(request, 409, `${role} is already connected`);
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.serializeAttachment({
      kind: "peer",
      role,
      forwardedMessages: 0,
    });
    this.state.acceptWebSocket(server, [role]);
    await this.ensureAlarm();
    this.notifyPeerReady();

    return new Response(null, { status: 101, webSocket: client });
  }

  /** @returns {ConnectedPeers} */
  connectedPeers() {
    const cli = this.state.getWebSockets("cli");
    const phone = this.state.getWebSockets("phone");

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

  notifyPeerReady() {
    const peers = this.connectedPeers();
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

  async ensureAlarm() {
    const alarm = await this.state.storage.getAlarm();
    if (alarm === null) {
      await this.state.storage.setAlarm(Date.now() + SIGNAL_SESSION_TTL_MS);
    }
  }

  /**
   * @param {Request} request
   * @param {SignalRole} role
   * @returns {Promise<Response>}
   */
  async fetchTurnCredential(request, role) {
    const peers = this.connectedPeers();
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

    const storageKey = `turn:${role}`;
    const cached = await this.state.storage.get(storageKey);
    if (typeof cached === "string") {
      return this.turnCredentialResponse(request, cached);
    }

    let pending = this.turnCredentialRequests.get(role);
    if (!pending) {
      pending = this.mintAndStoreTurnCredential(storageKey, config);
      this.turnCredentialRequests.set(role, pending);
    }

    try {
      const serialized = await pending;
      return this.turnCredentialResponse(request, serialized);
    } catch {
      return v2Error(request, 502, "TURN credential provider failed");
    } finally {
      if (this.turnCredentialRequests.get(role) === pending) {
        this.turnCredentialRequests.delete(role);
      }
    }
  }

  /**
   * @param {string} storageKey
   * @param {{ kind: "configured", keyId: string, apiToken: string }} config
   * @returns {Promise<string>}
   */
  async mintAndStoreTurnCredential(storageKey, config) {
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
    await this.state.storage.put(storageKey, serialized);
    return serialized;
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

    /** @type {SignalRole} */
    const role = attachment.role;
    /** @type {SignalRole} */
    const destinationRole = role === "cli" ? "phone" : "cli";
    const destinations = this.state.getWebSockets(destinationRole);
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
    for (const ws of this.state.getWebSockets()) {
      try { ws.close(1001, "session expired"); } catch {}
    }
    await this.state.storage.deleteAll();
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
    const destinationRole = role === "cli" ? "phone" : "cli";
    for (const peer of this.state.getWebSockets(destinationRole)) {
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
