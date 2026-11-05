import { createServer, request, type IncomingMessage, type ServerResponse, type OutgoingHttpHeaders } from "node:http";

const HOP_HEADERS = ["connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"];
function cleanHeaders(input: OutgoingHttpHeaders): OutgoingHttpHeaders {
  const headers = { ...input };
  const connection = String(headers.connection ?? "").toLowerCase().split(",").map(x => x.trim());
  for (const name of [...HOP_HEADERS, ...connection]) delete headers[name];
  return headers;
}

/** Shared by private HTTPS and the ingress backend. Forwarded identity is never trusted. */
export function gatewayHandler(origin: string, adminPort: number, mcpPort: number, ready = () => true) {
  const canonical = new URL(origin);
  return (req: IncomingMessage, res: ServerResponse) => {
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("Cache-Control", "no-store");
    // Health has no account, secret, network target or vault state in its response.
    if (req.url === "/healthz" || req.url === "/readyz") {
      if (req.method !== "GET" && req.method !== "HEAD") { res.writeHead(405).end(); return; }
      res.writeHead(req.url === "/readyz" && !ready() ? 503 : 200, { "Content-Type": "application/json" }).end('{"status":"ok"}'); return;
    }
    if (!ready()) { res.writeHead(503).end("Shutting down"); return; }
    if (req.headers.host !== canonical.host) { res.writeHead(403).end("Forbidden host"); return; }
    if (req.headers.origin && req.headers.origin !== canonical.origin) { res.writeHead(403).end("Forbidden origin"); return; }
    // Reject ambiguous paths before URL normalization or Express decoding can change routing.
    const raw = req.url ?? "/";
    const path = raw.split("?", 1)[0];
    if (!raw.startsWith("/") || raw.startsWith("//") || /[%\\\x00-\x20]/.test(path) || path.split("/").some(p => p === "." || p === "..")) { res.writeHead(400).end("Invalid path"); return; }
    if (/^\/identity\/bootstrap(?:\/|$)/i.test(path)) { res.writeHead(403).end("Bootstrap is loopback-only"); return; }
    const mcp = path === "/mcp" || path.startsWith("/.well-known/") || ["/token", "/authorize", "/register", "/revoke"].includes(path.replace(/\/$/, ""));
    const port = mcp ? mcpPort : adminPort;
    const headers = cleanHeaders(req.headers);
    for (const name of Object.keys(headers)) if (name.startsWith("x-forwarded-") || name === "forwarded" || name === "x-mcp-private-gateway") delete headers[name];
    headers.host = `127.0.0.1:${port}`;
    headers["x-mcp-private-gateway"] = "1";
    const upstream = request({ hostname: "127.0.0.1", port, method: req.method, path: raw, headers }, response => {
      res.writeHead(response.statusCode ?? 502, cleanHeaders(response.headers)); response.pipe(res);
    });
    upstream.setTimeout(650_000, () => upstream.destroy());
    upstream.on("error", () => { if (!res.headersSent) res.writeHead(502); res.end("Gateway unavailable"); });
    req.on("aborted", () => upstream.destroy()); res.on("close", () => upstream.destroy()); req.pipe(upstream);
  };
}

/** HTTP is only the backend of a TLS terminator; publish this port on loopback or an isolated pod network. */
export function startGateway(origin: string, adminPort: number, mcpPort: number, port: number, bind: string, ready: () => boolean) {
  const server = createServer(gatewayHandler(origin, adminPort, mcpPort, ready));
  server.requestTimeout = 660_000;
  server.headersTimeout = 15_000;
  server.maxHeadersCount = 100;
  server.listen(port, bind, () => console.log(`Gateway backend http://${bind}:${port} (TLS reverse proxy required)`));
  return server;
}
