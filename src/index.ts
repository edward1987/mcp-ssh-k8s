import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { startAdmin } from "./admin/server.js";
import { Audit } from "./audit.js";
import { startMcp } from "./mcp/server.js";
import { HostMonitor } from "./health.js";
import { Approvals } from "./policy/policy.js";
import { TunnelManager } from "./tunnel/manager.js";
import { Vault } from "./vault/store.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dataDir = process.env.MCP_SSH_DATA ?? join(root, "data");

const vault = new Vault(join(dataDir, "vault.json"));
const ctx = {
  vault,
  audit: new Audit(join(dataDir, "audit.jsonl")),
  approvals: new Approvals(),
  monitor: new HostMonitor(vault),
};

const mcpPort = Number(process.env.MCP_PORT ?? 7778);
const tunnel = new TunnelManager(ctx.vault, dataDir, mcpPort);

startAdmin(ctx, Number(process.env.ADMIN_PORT ?? 7777), join(root, "web"), tunnel, { dataDir, scriptsDir: join(root, "scripts") });
startMcp(ctx, mcpPort);

for (const sig of ["SIGINT", "SIGTERM"] as const)
  process.on(sig, () => {
    tunnel.stop();
    process.exit(0);
  });
process.on("exit", () => tunnel.stop());
