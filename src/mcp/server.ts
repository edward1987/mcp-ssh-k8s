import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { findHost, formatResult, runCommand, shq, type Ctx } from "../service.js";

function buildServer(ctx: Ctx, client: string) {
  const server = new McpServer({ name: "mcp-ssh", version: "0.1.0" });
  const text = (t: string, isError = false) => ({ content: [{ type: "text" as const, text: t }], isError });
  const guard = async (fn: () => Promise<string>) => {
    try {
      return text(await fn());
    } catch (e) {
      return text((e as Error).message, true);
    }
  };

  server.registerTool(
    "list_hosts",
    { description: "List configured SSH hosts (name, address, user, safety mode). Never returns secrets." },
    async () =>
      guard(async () =>
        JSON.stringify(
          ctx.vault.d.hosts.map((h) => ({ name: h.name, address: `${h.hostname}:${h.port}`, user: h.user, mode: h.mode, group: h.group, tags: h.tags })),
          null,
          2,
        ),
      ),
  );

  server.registerTool(
    "run_command",
    {
      description:
        "Run a shell command on a host over SSH. Host safety mode applies: read-only hosts only accept allowlisted single commands (no pipes/redirects); approval hosts wait for the operator to approve in the web UI.",
      inputSchema: {
        host: z.string().describe("Host name from list_hosts"),
        command: z.string().min(1),
        timeout_seconds: z.number().int().min(1).max(600).default(30).optional(),
      },
    },
    async ({ host, command, timeout_seconds }) =>
      guard(async () => formatResult(await runCommand(ctx, client, host, command, timeout_seconds ?? 30))),
  );

  server.registerTool(
    "read_file",
    {
      description: "Read a text file on a host (same policy as run_command; output size limited).",
      inputSchema: { host: z.string(), path: z.string().min(1) },
    },
    async ({ host, path }) => guard(async () => formatResult(await runCommand(ctx, client, host, `cat -- ${shq(path)}`, 30, "read_file"))),
  );

  server.registerTool(
    "get_host_info",
    {
      description: "Quick system summary of a host (uname, uptime, disk, memory).",
      inputSchema: { host: z.string() },
    },
    async ({ host }) => {
      findHost(ctx.vault, host);
      return guard(async () => {
        const out: string[] = [];
        for (const c of ["uname -a", "uptime", "df -h", "free -m"]) {
          out.push(`$ ${c}\n` + formatResult(await runCommand(ctx, client, host, c, 20, "get_host_info")));
        }
        return out.join("\n\n");
      });
    },
  );

  return server;
}

export function startMcp(ctx: Ctx, port: number, bind = "127.0.0.1") {
  const app = express();
  app.disable("x-powered-by");
  app.use(express.json({ limit: "1mb" }));

  const failures = new Map<string, { n: number; until: number }>();

  app.use("/mcp", (req, res, next) => {
    const ip = req.ip ?? "?";
    const f = failures.get(ip);
    if (f && f.n >= 10 && Date.now() < f.until) return void res.status(429).json({ error: "too many failures" });
    const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? "");
    if (!ctx.vault.unlocked) return void res.status(503).json({ error: "vault locked - unlock it in the web UI" });
    const tok = m ? ctx.vault.verifyToken(m[1]) : null;
    if (!tok) {
      const cur = f ?? { n: 0, until: 0 };
      failures.set(ip, { n: cur.n + 1, until: Date.now() + 60_000 });
      return void res.status(401).json({ error: "unauthorized" });
    }
    failures.delete(ip);
    (req as any).clientName = tok.name;
    next();
  });

  app.post("/mcp", async (req, res) => {
    const server = buildServer(ctx, (req as any).clientName);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => {
      transport.close();
      server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  });

  // Discovery probes (e.g. OAuth protected-resource metadata) get a JSON 404 instead of an HTML page.
  app.use("/.well-known", (_req, res) => res.status(404).json({ error: "not_found" }));

  const notAllowed = (_: express.Request, res: express.Response) =>
    res.status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed" }, id: null });
  app.get("/mcp", notAllowed);
  app.delete("/mcp", notAllowed);

  return app.listen(port, bind, () => console.log(`MCP endpoint  http://${bind}:${port}/mcp  (expose THIS port via tunnel)`));
}
