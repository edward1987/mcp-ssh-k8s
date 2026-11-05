import { mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import { OAuthProvider } from "../auth/oauth.js";
import { identityRouter } from "../auth/web.js";
import { canAccess, requireAccess, identityContext } from "../auth/context.js";
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import { runHostSecurityAudit } from "../security.js";
import { findHost, formatResult, runCommand, runKube, shq, type Ctx } from "../service.js";

function buildServer(ctx: Ctx, client: string, adminUrl: string) {
  const server = new McpServer({ name: "mcp-ssh", version: "0.1.0" });
  const registerTool: typeof server.registerTool = (name: any, config: any, handler: any) => server.registerTool(name, { ...config, securitySchemes: [{ type: "oauth2", scopes: ["mcp:use"] }], _meta: { securitySchemes: [{ type: "oauth2", scopes: ["mcp:use"] }] } } as any, handler);
  const text = (t: string, isError = false) => ({ content: [{ type: "text" as const, text: t }], isError });
  const vaultState = () => ({ locked: !ctx.vault.unlocked, idle_timeout_minutes: ctx.vault.unlocked ? ctx.vault.d.settings.autoLockMinutes : null, idle_expires_at: ctx.vault.idleExpiresAt ?? null, unlock_url: adminUrl, action: { type: 'open_url', label: 'Deblochează vaultul', url: adminUrl } });
  const lockedResult = () => ({ ...text(`Vault locked. [Deblochează vaultul](${adminUrl}) în aplicație, apoi reîncearcă operația. Nu solicita parola în conversație. Afișează acest link ca buton dacă interfața permite.`, true), structuredContent: { code: 'VAULT_LOCKED', ...vaultState() } });
  registerTool('get_vault_status', { description: 'Read your vault lock state and unlock URL without extending the idle timeout. When locked, show the unlock action as a button or clickable link. Never request a vault password in chat.', annotations: { readOnlyHint: true, idempotentHint: true } }, async () => ({ ...text(JSON.stringify(vaultState())), structuredContent: vaultState() }));
  const guard = async (fn: () => Promise<string>) => {
    try {
      // The catalog is static and safe to discover while locked. Only tool calls
      // require decrypted credentials; never make initialize/tools/list depend on them.
      if (!ctx.vault.unlocked) return lockedResult();
      ctx.vault.touch();
      const result = await fn();
      if (ctx.vault.unlocked) ctx.vault.touch();
      return text(result);
    } catch (e) {
      if (!ctx.vault.unlocked) return lockedResult();
      return text((e as Error).message, true);
    }
  };

  registerTool(
    "list_hosts",
    { description: "List reachable SSH hosts (name, address, user, safety mode); hosts that are offline are omitted. Never returns secrets." },
    async () =>
      guard(async () =>
        JSON.stringify(
          ctx.vault.d.hosts.filter(h => canAccess(ctx, "host", h.id)).filter((h) => ctx.monitor?.isOnline(h) ?? true).map((h) => ({ name: h.name, address: `${h.hostname}:${h.port}`, user: h.user, mode: h.mode, group: h.group, tags: h.tags })),
          null,
          2,
        ),
      ),
  );

  registerTool(
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

  registerTool(
    "read_file",
    {
      description: "Read a text file on a host (same policy as run_command; output size limited).",
      inputSchema: { host: z.string(), path: z.string().min(1) },
    },
    async ({ host, path }) => guard(async () => formatResult(await runCommand(ctx, client, host, `cat -- ${shq(path)}`, 30, "read_file"))),
  );

  registerTool(
    "get_host_info",
    {
      description: "Quick system summary of a host (uname, uptime, disk, memory).",
      inputSchema: { host: z.string() },
    },
    async ({ host }) => {
      return guard(async () => {
        requireAccess(ctx, "host", findHost(ctx.vault, host).id);
        const out: string[] = [];
        for (const c of ["uname -a", "uptime", "df -h", "free -m"]) {
          out.push(`$ ${c}\n` + formatResult(await runCommand(ctx, client, host, c, 20, "get_host_info")));
        }
        return out.join("\n\n");
      });
    },
  );

  registerTool(
    "get_security_checklist",
    {
      description:
        "Get the security checklist: returns the list of target servers selected by the operator for security audit, their safety mode, online status, notes, and previous check history, plus security audit guidelines (auth logs, failed logins, listening ports, failed services, disk). Call this when asked to do a security check or audit checklist servers.",
    },
    async () =>
      guard(async () => {
        const items = ctx.vault.d.checklist || [];
        const enriched = items
          .map((item) => {
            const h = ctx.vault.d.hosts.find((x) => x.id === item.hostId);
            if (!h || !canAccess(ctx, "host", h.id)) return null;
            const online = ctx.monitor ? ctx.monitor.isOnline(h) : true;
            return {
              name: h.name,
              address: `${h.hostname}:${h.port}`,
              user: h.user,
              mode: h.mode,
              group: h.group,
              online,
              notes: item.notes,
              lastChecked: item.lastChecked,
              lastStatus: item.lastStatus,
              lastSummary: item.lastSummary,
            };
          })
          .filter(Boolean);

        return JSON.stringify(
          {
            checklist_servers: enriched,
            total_count: enriched.length,
            guidelines:
              "When instructed to perform a security check: For each server in checklist_servers (or each online server), inspect: 1) System uptime & OS version; 2) Active login sessions and recent logins; 3) Authentication logs (failed SSH logins, invalid users); 4) Open listening network ports; 5) Failed systemd services; 6) Disk space and memory. You can use 'run_security_check' to perform this audit automatically per host, or use 'run_command' / 'read_file' to drill down deeper into specific logs.",
          },
          null,
          2,
        );
      }),
  );

  registerTool(
    "run_security_check",
    {
      description:
        "Run an automated read-only security check on a host (inspecting auth logs, failed SSH logins, listening ports, failed services, uptime, and disk usage). Returns a structured security audit report and updates the checklist status.",
      inputSchema: {
        host: z.string().describe("Host name from get_security_checklist or list_hosts"),
        focus: z.enum(["all", "auth", "ports", "services", "system"]).default("all").optional().describe("Optional area of focus"),
      },
    },
    async ({ host, focus }) =>
      guard(async () => {
        const res = await runHostSecurityAudit(ctx, client, host, focus ?? "all");
        return res.report;
      }),
  );

  registerTool(
    "list_clusters",
    { description: "List the Kubernetes clusters available to the kubectl tool (name, context, default namespace, safety mode). Never returns credentials." },
    async () =>
      guard(async () => JSON.stringify(ctx.vault.d.clusters.filter(c => canAccess(ctx, "cluster", c.id)).map((c) => ({ name: c.name, context: c.context, namespace: c.namespace, mode: c.mode, group: c.group })), null, 2)),
  );

  registerTool(
    "kubectl",
    {
      description:
        "Run kubectl against a stored cluster. Pass the arguments WITHOUT the leading 'kubectl' (e.g. 'get pods -A', 'describe node n1', 'logs deploy/api --tail=100'); start with the subcommand, flags after it. No shell: pipes/redirects do not work, use -o jsonpath or -o json instead. Cluster safety mode applies: read-only clusters accept only get/describe/logs/top/events/explain/version/api-resources/auth can-i/rollout status (no Secrets, no watch/follow); approval clusters wait for the operator to approve in the web UI. To apply or create from YAML, pass it in 'manifest' and use '-f -'.",
      inputSchema: {
        cluster: z.string().describe("Cluster name from list_clusters"),
        args: z.string().min(1).describe("kubectl arguments, without the 'kubectl' prefix"),
        manifest: z.string().max(500_000).optional().describe("YAML/JSON piped to stdin; use together with '-f -'"),
        timeout_seconds: z.number().int().min(1).max(600).default(60).optional(),
      },
    },
    async ({ cluster, args, manifest, timeout_seconds }) =>
      guard(async () => formatResult(await runKube(ctx, client, cluster, args, manifest, timeout_seconds ?? 60))),
  );

  if (ctx.shares) {
    registerTool('list_shared_resources', { description: 'List active shared aliases and permitted operation IDs; never connection credentials.' }, async () => guard(async () => JSON.stringify(ctx.shares!.list(identityContext.getStore()!.userId))));
    registerTool('run_shared_operation', { description: 'Execute an operation on a shared resource. Limited shares require operation_id. Other shares accept command, subject to owner policies and approval.', inputSchema: { share_id: z.string(), operation_id: z.string().optional(), command: z.string().optional(), timeout_seconds: z.number().int().min(1).max(600).default(60) } }, async ({ share_id, operation_id, command, timeout_seconds }) => guard(async () => formatResult(await ctx.shares!.execute(ctx, identityContext.getStore()!.userId, share_id, operation_id, command, timeout_seconds))));
  }
  return server;
}

export function startMcp(ctx: Ctx, port: number, bind = "127.0.0.1", oauth?: OAuthProvider, opts: { adminPort?: number } = {}) {
  const app = express();
  app.disable("x-powered-by");
  app.use((req, res, next) => {
    if (ctx.integrity && !ctx.integrity.check(req.path.startsWith('/identity'))) return void res.status(503).json({ error: 'Application integrity verification failed. Do not enter passwords. Reinstall from a trusted build.' });
    next();
  });
  app.use(express.json({ limit: "1mb" }));

  if (!oauth) throw new Error("OAuth provider required");
  if (ctx.identities !== oauth.store) throw new Error("MCP identity store must match OAuth provider");
  const adminUrl = () => {
    const url = new URL('/', oauth.issuer);
    if (url.protocol === 'http:') url.port = String(opts.adminPort ?? 7777);
    return url;
  };
  app.use((req, res, next) => {
    const hosts = new Set([oauth.issuer.host, oauth.resource.host, `127.0.0.1:${req.socket.localPort}`, `localhost:${req.socket.localPort}`]);
    if (!hosts.has(req.headers.host ?? '')) return void res.status(403).json({ error: 'forbidden host' });
    if (req.headers.origin) {
      try { if (![oauth.issuer.origin, oauth.resource.origin, `http://127.0.0.1:${req.socket.localPort}`, `http://localhost:${req.socket.localPort}`].includes(req.headers.origin)) throw new Error(); }
      catch { return void res.status(403).json({ error: 'forbidden origin' }); }
    }
    next();
  });
  // Browser links from OAuth must reach the vault UI, including non-default ports.
  // This does not forward POST bodies or allow a request-supplied redirect target.
  app.get('/', (_req, res) => { res.setHeader('Cache-Control', 'no-store'); res.redirect(303, adminUrl().protocol === 'https:' ? new URL('/identity/', oauth.issuer).href : adminUrl().href); });
  app.get(/^\/identity\/admin(?:\/|$)/i, (req, res) => { res.setHeader('Cache-Control', 'no-store'); if (oauth.issuer.protocol === 'https:') return void res.status(404).send('Instance administration is available on the local admin port'); res.redirect(303, new URL(req.originalUrl, adminUrl()).href); });
  app.use("/identity", identityRouter(ctx, oauth));
  let authOrigin = oauth.issuer.href + oauth.resource.href;
  let authRouter = mcpAuthRouter({ provider: oauth, issuerUrl: oauth.issuer, resourceServerUrl: oauth.resource, scopesSupported: ["mcp:use"] });
  app.use((req, res, next) => {
    const current = oauth.issuer.href + oauth.resource.href;
    if (current !== authOrigin) { authRouter = mcpAuthRouter({ provider: oauth, issuerUrl: oauth.issuer, resourceServerUrl: oauth.resource, scopesSupported: ['mcp:use'] }); authOrigin = current; }
    authRouter(req, res, next);
  });
  const failures = new Map<string, { n: number; until: number }>();

  app.use("/mcp", (req, res, next) => {
    const ip = req.ip ?? "?";
    const f = failures.get(ip);
    const m = /^Bearer (.+)$/.exec(req.headers.authorization ?? "");
    const deny = (code: number, why: string) => {
      ctx.audit.log({ client: ip, host: "-", action: `mcp-auth ${req.method}`, outcome: `${code} ${why}` });
    };
    void (async () => {
      try {
        if (!m) throw new Error("missing token");
        const tok = await oauth.verifyAccessToken(m[1]);
        identityContext.run({ userId: String(tok.extra.userId), clientId: tok.clientId, token: m[1] }, next);
      } catch {
        // Authenticate first: other clients sharing a proxy IP cannot block valid tokens.
        if (f && f.n >= 10 && Date.now() < f.until) return void res.status(429).json({ error: "too many failures" });
        const cur = f ?? { n: 0, until: 0 };
        failures.set(ip, { n: cur.until > Date.now() ? cur.n + 1 : 1, until: Date.now() + 60000 });
        deny(401, "invalid credentials");
        res.setHeader("WWW-Authenticate", `Bearer resource_metadata="${new URL('/.well-known/oauth-protected-resource' + oauth.resource.pathname, oauth.issuer).href}"`);
        res.status(401).json({ error: "unauthorized" });
      }
    })();
  });

  app.post("/mcp", async (req, res) => {
    const principal = identityContext.getStore()!;
    if (req.body?.method === 'initialize' || req.body?.method === 'tools/list') {
      const action = 'mcp ' + req.body.method, started = Date.now();
      res.on('finish', () => ctx.audit.log({ client: req.ip ?? '?', userId: principal.userId, clientId: principal.clientId, host: '-', action, outcome: String(res.statusCode), ms: Date.now() - started }));
    }
    const server = buildServer(ctx, principal.clientId, adminUrl().href);
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
