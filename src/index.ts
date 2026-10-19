import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { startAdmin } from "./admin/server.js";
import { Audit } from "./audit.js";
import { startMcp } from "./mcp/server.js";
import { Approvals } from "./policy/policy.js";
import { Vault } from "./vault/store.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dataDir = process.env.MCP_SSH_DATA ?? join(root, "data");

const ctx = {
  vault: new Vault(join(dataDir, "vault.json")),
  audit: new Audit(join(dataDir, "audit.jsonl")),
  approvals: new Approvals(),
};

startAdmin(ctx, Number(process.env.ADMIN_PORT ?? 7777), join(root, "web"));
startMcp(ctx, Number(process.env.MCP_PORT ?? 7778));
