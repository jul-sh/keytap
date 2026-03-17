export interface Env {
  RELAY_SESSION: DurableObjectNamespace;
}

const CORS_ORIGINS = new Set([
  "https://tapkey.jul.sh",
  "http://localhost:8080",
  "http://localhost:3000",
]);

function corsHeaders(request: Request): HeadersInit {
  const origin = request.headers.get("Origin") || "";
  const allowed = CORS_ORIGINS.has(origin) ? origin : "";
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const match = url.pathname.match(/^\/relay\/([a-zA-Z0-9_-]{22,44})$/);
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

export class RelaySession implements DurableObject {
  constructor(private state: DurableObjectState, _env: Env) {}

  async fetch(request: Request): Promise<Response> {
    // WebSocket upgrade (CLI connects here)
    if (request.headers.get("Upgrade") === "websocket") {
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      this.state.acceptWebSocket(server);
      return new Response(null, { status: 101, webSocket: client });
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

      // Push to all connected WebSockets (should be exactly one: the CLI)
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

      // Close WebSockets after delivery
      for (const ws of this.state.getWebSockets()) {
        try {
          ws.close(1000, "delivered");
        } catch {
          // already closed
        }
      }

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

  async webSocketMessage(): Promise<void> {}

  async webSocketClose(ws: WebSocket): Promise<void> {
    try { ws.close(); } catch {}
  }

  async webSocketError(ws: WebSocket): Promise<void> {
    try { ws.close(1011, "error"); } catch {}
  }
}
