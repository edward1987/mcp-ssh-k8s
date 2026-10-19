# mcp-ssh

MCP server that lets AI clients (Claude, ChatGPT, ...) run commands on your SSH hosts. Hosts, keys and tokens are managed in a local web UI and stored in an encrypted vault.

## Run
    npm install
    npm run dev          # or: npm run build && npm start

- Admin UI: http://127.0.0.1:7777 (loopback only, never expose it). First visit creates the vault (master password, min 12 chars).
- MCP endpoint: http://127.0.0.1:7778/mcp (Streamable HTTP, `Authorization: Bearer <token>`). Create tokens in the UI.
- Tunnel only the MCP port, e.g. `cloudflared tunnel --url http://127.0.0.1:7778`.
- Env: `ADMIN_PORT`, `MCP_PORT`, `MCP_SSH_DATA` (default `./data`).

Claude Code: `claude mcp add --transport http ssh http://127.0.0.1:7778/mcp --header "Authorization: Bearer <token>"`

## Security model
- Vault: AES-256-GCM, key from scrypt(N=2^17) of the master password; nothing secret on disk in clear. Auto-locks after inactivity; MCP returns 503 while locked.
- MCP tokens are stored as SHA-256 hashes, shown once, revocable; failed auth is rate limited.
- Per-host mode: `read-only` (allowlisted single commands, no shell metacharacters), `approval` (operator approves in the UI), `free`.
- Host keys are pinned on first use; a changed key is refused.
- Every call is logged to `data/audit.jsonl` (no secrets).

## Import
UI > Import: `~/.ssh/config` (+ referenced keys) or Termius CSV (hosts only; Termius does not export private keys).

## Not done yet
OAuth for connectors that require it (ChatGPT), ProxyJump, file upload/download, Argon2id (scrypt used to avoid native deps).
