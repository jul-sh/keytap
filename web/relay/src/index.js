const CORS_ORIGINS = new Set([
  "https://keytap.jul.sh",
]);

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

export default {
  /**
   * @param {Request} request
   * @param {{ RELAY_SESSION: DurableObjectNamespace }} env
   * @returns {Promise<Response>}
   */
  async fetch(request, env) {
    const url = new URL(request.url);
    const match = url.pathname.match(/^\/relay\/([a-zA-Z0-9_-]{8,44})$/);
    if (!match) {
      return new Response("Not found", { status: 404 });
    }

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    const sessionId = match[1];
    const id = env.RELAY_SESSION.idFromName(sessionId);
    const stub = env.RELAY_SESSION.get(id);
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
