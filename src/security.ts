import { findHost, formatResult, type Ctx } from "./service.js";
import { runSsh } from "./ssh/exec.js";
import type { Host } from "./vault/store.js";

export interface SecurityAuditResult {
  host: string;
  timestamp: string;
  status: "ok" | "warning";
  summary: string;
  report: string;
  details: {
    system?: string;
    logins?: string;
    failedAuth?: string;
    ports?: string;
    services?: string;
    disk?: string;
  };
}

/**
 * Runs a structured, read-only security audit on an SSH host:
 * 1. System info & uptime
 * 2. Active sessions and recent logins (w / last)
 * 3. Failed SSH login attempts / auth logs
 * 4. Open listening ports (ss -tulpn)
 * 5. Failed systemd units
 * 6. Disk space & memory
 */
export async function runHostSecurityAudit(
  ctx: Ctx,
  client: string,
  hostRef: string,
  focus?: "all" | "auth" | "ports" | "services" | "system",
): Promise<SecurityAuditResult> {
  const { vault, audit, approvals } = ctx;
  vault.touch();
  const host = findHost(vault, hostRef);

  if (ctx.monitor && !ctx.monitor.isOnline(host)) {
    throw new Error(`host "${host.name}" is offline (use list_hosts or get_security_checklist for status)`);
  }

  // Operator in UI is trusted; MCP client must adhere to host mode
  if (client !== "operator" && host.mode === "approval") {
    const d = await approvals.request(
      {
        host: host.name,
        command: "security-audit: inspect auth logs, listening ports, failed services, disk & resources",
        client,
      },
      vault.d.settings.approvalTimeoutSec,
    );
    if (d !== "approved") {
      audit.log({ client, host: host.name, action: "security_audit", command: "security-audit", mode: host.mode, outcome: d });
      throw new Error(d === "denied" ? "Security check denied by operator." : "Timed out waiting for operator approval.");
    }
  }

  const exec = async (cmd: string): Promise<string> => {
    try {
      const res = await runSsh(vault, host, cmd, 15);
      return formatResult(res).trim();
    } catch (e) {
      return `[error executing "${cmd}": ${(e as Error).message}]`;
    }
  };

  const warnings: string[] = [];
  const details: SecurityAuditResult["details"] = {};

  // 1. System Overview
  let sysOut = "";
  if (!focus || focus === "all" || focus === "system") {
    const uname = await exec("uname -a");
    const uptime = await exec("uptime");
    sysOut = `OS: ${uname}\nUptime: ${uptime}`;
    details.system = sysOut;
  }

  // 2. Logins & Auth
  let loginOut = "";
  let failedOut = "";
  if (!focus || focus === "all" || focus === "auth") {
    const w = await exec("w");
    const last = await exec("last -n 5");
    loginOut = `--- Logged In (w) ---\n${w}\n\n--- Recent Logins (last -n 5) ---\n${last}`;
    details.logins = loginOut;

    // Check failed auth attempts
    let sshLogs = await exec("journalctl -u ssh -p err --no-pager -n 30");
    if (!sshLogs || sshLogs.includes("No entries") || sshLogs.includes("error")) {
      sshLogs = await exec("journalctl -u sshd -p err --no-pager -n 30");
    }
    if (!sshLogs || sshLogs.includes("No entries") || sshLogs.includes("error")) {
      sshLogs = await exec("grep -i failed /var/log/auth.log");
    }
    failedOut = sshLogs || "(no failed ssh/auth log entries found)";
    details.failedAuth = failedOut;

    // Check for high volume of failed attempts
    const failedMatches = (failedOut.match(/failed|failure|invalid user/gi) || []).length;
    if (failedMatches > 10) {
      warnings.push(`${failedMatches} failed login attempts detected in recent logs`);
    }
  }

  // 3. Listening Ports
  let portsOut = "";
  if (!focus || focus === "all" || focus === "ports") {
    portsOut = await exec("ss -tulpn");
    if (portsOut.includes("error") || !portsOut) {
      portsOut = await exec("netstat -tulpn");
    }
    details.ports = portsOut;
  }

  // 4. Failed Services
  let servOut = "";
  if (!focus || focus === "all" || focus === "services") {
    servOut = await exec("systemctl list-units --failed");
    details.services = servOut;
    if (servOut && !servOut.includes("0 loaded units listed") && !servOut.includes("error") && servOut.includes("failed")) {
      warnings.push("Failed systemd services detected");
    }
  }

  // 5. Disk & Resources
  let diskOut = "";
  if (!focus || focus === "all" || focus === "system") {
    const df = await exec("df -h");
    const free = await exec("free -m");
    diskOut = `--- Disk Space (df -h) ---\n${df}\n\n--- Memory (free -m) ---\n${free}`;
    details.disk = diskOut;

    // Check disk usage > 90%
    const lines = df.split("\n");
    for (const l of lines) {
      const match = /(\d{1,3})%\s+(\/.*)$/.exec(l);
      if (match && parseInt(match[1], 10) >= 90) {
        warnings.push(`Partition ${match[2]} is ${match[1]}% full`);
      }
    }
  }

  const status: "ok" | "warning" = warnings.length > 0 ? "warning" : "ok";
  const summary = warnings.length > 0 ? `Atenție: ${warnings.join(", ")}` : "OK - Nicio problemă critică detectată";
  const ts = new Date().toISOString();

  const reportParts: string[] = [
    `# Security Audit Report: ${host.name} (${host.hostname})`,
    `**Data:** ${ts.replace("T", " ").slice(0, 19)} | **Status:** ${status.toUpperCase()} | **Utilizator:** ${host.user} | **Mod:** ${host.mode}`,
    warnings.length ? `\n> ⚠️ **Alerte identificate:**\n> - ${warnings.join("\n> - ")}\n` : "\n> ✅ Toate verificările de bază au trecut cu succes.\n",
  ];

  if (details.system) reportParts.push(`### 1. Sistem & Uptime\n\`\`\`\n${details.system}\n\`\`\``);
  if (details.logins) reportParts.push(`### 2. Sesiuni Active & Logări Recente\n\`\`\`\n${details.logins}\n\`\`\``);
  if (details.failedAuth) reportParts.push(`### 3. Loguri Autentificare & Tentative Eșuate\n\`\`\`\n${details.failedAuth}\n\`\`\``);
  if (details.ports) reportParts.push(`### 4. Porturi Deschise & Servicii în Ascultare\n\`\`\`\n${details.ports}\n\`\`\``);
  if (details.services) reportParts.push(`### 5. Servicii de Sistem Picat (Systemd)\n\`\`\`\n${details.services}\n\`\`\``);
  if (details.disk) reportParts.push(`### 6. Spațiu Disc & Memorie\n\`\`\`\n${details.disk}\n\`\`\``);

  const report = reportParts.join("\n\n");

  // Update checklist record in vault if host is in checklist
  const item = vault.d.checklist.find((c) => c.hostId === host.id);
  if (item) {
    item.lastChecked = ts;
    item.lastStatus = status;
    item.lastSummary = summary;
    vault.save();
  }

  audit.log({
    client,
    host: host.name,
    action: "security_audit",
    command: focus ? `security-audit (${focus})` : "security-audit",
    mode: host.mode,
    outcome: status === "ok" ? "ok" : `warn (${warnings.length} alerts)`,
  });

  return {
    host: host.name,
    timestamp: ts,
    status,
    summary,
    report,
    details,
  };
}
