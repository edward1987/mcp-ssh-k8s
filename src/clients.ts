export const CLIENTS = [
  { id: "claude-desktop", name: "Claude Desktop", transport: "stdio" },
  { id: "codex-desktop", name: "Codex Desktop", transport: "http" },
  { id: "codex-cli", name: "Codex CLI", transport: "http" },
  { id: "claude-cli", name: "Claude CLI (Claude Code)", transport: "http" },
  { id: "claude-web", name: "Claude Web", transport: "http" },
  { id: "gemini-web", name: "Gemini Web", transport: "http" },
  { id: "gemini-cli", name: "Gemini CLI", transport: "http" },
] as const;

export function clientSetup(clientId: string, token: string, opts: { endpoint: string; nodePath: string; bridgePath: string }) {
  const client = CLIENTS.find((c) => c.id === clientId);
  if (!client) throw new Error("unknown MCP client");
  const q = JSON.stringify;
  const blocks: { title: string; content: string }[] = [];
  let instructions = "Conecteaza clientul si autentifica-te prin OAuth folosind contul propriu si MFA. Nu adauga tokenuri sau parole in workspace.";
  if (client.id === "claude-desktop") {
    blocks.push({ title: "claude_desktop_config.json", content: q({ mcpServers: { ssh: { command: opts.nodePath, args: [opts.bridgePath], env: { MCP_SSH_URL: opts.endpoint } } } }, null, 2) });
    instructions += " Bridge-ul afiseaza URL-ul de login in logurile MCP; deschide-l in browser.";
  } else if (client.id === "claude-cli") {
    blocks.push({ title: "Terminal", content: `claude mcp add --scope user --transport http ssh ${opts.endpoint}\nclaude mcp login ssh` });
  } else if (client.id === "gemini-cli") {
    blocks.push({ title: "~/.gemini/settings.json (imbina cu setarile existente)", content: q({ mcpServers: { ssh: { httpUrl: opts.endpoint, timeout: 660000 } } }, null, 2) });
    blocks.push({ title: "In Gemini CLI", content: "/mcp auth ssh" });
  } else if (client.id === "claude-web" || client.id === "gemini-web") {
    const https = new URL(opts.endpoint).protocol === 'https:';
    instructions += https ? " Endpointul HTTPS si paginile OAuth trebuie sa fie accesibile public din infrastructura furnizorului." : " Configureaza mai intai HTTPS public in Administrare instanta; adresa loopback nu este accesibila din web.";
    instructions += client.id === "claude-web" ? " In Claude: Settings > Connectors > Add custom connector. Adauga URL-ul MCP si autorizeaza contul propriu." : " In Gemini Web: Settings > Apps / Custom apps, adauga URL-ul MCP si autorizeaza contul propriu. Daca optiunea nu apare, foloseste Gemini Apps Developer Mode la https://gemini.google.com/devmode (disponibilitatea depinde de cont).";
    blocks.push({ title: "MCP Server URL", content: opts.endpoint });
  } else {
    blocks.push({ title: "config.toml - Codex Desktop / CLI", content: `[mcp_servers.ssh]\nurl = ${q(opts.endpoint)}\ntool_timeout_sec = 660` });
    blocks.push({ title: "Terminal", content: "codex mcp login ssh" });
  }
  return { client: client.id, name: client.name, endpoint: opts.endpoint, instructions, blocks };
}
