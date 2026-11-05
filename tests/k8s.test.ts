import { describe, expect, it } from "vitest";
import { checkKubectl, inspectKubeconfig, splitArgs, withDefaults, runKubectl, kubectlEnvironment } from "../src/k8s/kubectl.js";

const ok = (a: string, mode: any = "read-only", stdin = false) => checkKubectl(splitArgs(a), mode, stdin).ok;
const reason = (a: string, mode: any = "read-only", stdin = false) => {
  const r = checkKubectl(splitArgs(a), mode, stdin);
  return r.ok ? "" : r.reason;
};

describe("splitArgs", () => {
  it("handles quotes without a shell", () => {
    expect(splitArgs(`get pods -l "app=a b" -o 'jsonpath={.items[*].metadata.name}'`)).toEqual(["get", "pods", "-l", "app=a b", "-o", "jsonpath={.items[*].metadata.name}"]);
    expect(splitArgs(`get pods; rm -rf /`)).toEqual(["get", "pods;", "rm", "-rf", "/"]);
    expect(() => splitArgs(`get "pods`)).toThrow("unterminated");
  });
});

describe("kubectl policy", () => {
  it('blocks local writes and profiling in every mode, including normalized flag spellings', () => {
    for (const mode of ['read-only', 'approval', 'free']) {
      for (const command of ['cluster-info dump', 'cluster-info dump --output-directory=/tmp/proof', 'get pods --output_directory=/tmp/proof', 'get pods --profile=cpu', 'get pods --profile-output=/tmp/proof', 'get pods --profile_output /tmp/proof']) expect(ok(command, mode), `${mode}: ${command}`).toBe(false);
      expect(ok('cluster-info', mode)).toBe(true);
      expect(ok('exec pod -- command --profile=cpu', 'free')).toBe(true);
    }
  });
  it("allows read verbs in read-only", () => {
    for (const c of ["get pods -A", "describe node n1", "logs deploy/api --tail=50", "top pods", "get events -n kube-system", "auth can-i list pods", "rollout status deploy/x"])
      expect(ok(c), c).toBe(true);
  });
  it("blocks writes, secrets, watch and local files in read-only", () => {
    for (const c of ["delete pod x", "apply -f https://x/y.yaml", "exec pod -- ls", "get secrets", "get secret/foo -o yaml", "get pods,secrets", "get pods -w", "logs -f pod", "get --raw /api/v1/secrets", "rollout restart deploy/x", "auth reconcile"])
      expect(ok(c), c).toBe(false);
  });
  it("never lets the caller change the cluster identity or read local files", () => {
    for (const m of ["approval", "free"]) {
      for (const c of ["get pods --kubeconfig /x", "get pods --server=https://evil", "get pods -s https://evil", "get pods --token abc", "get pods --context other", "get pods --as admin",
        "apply -f /etc/passwd", "apply -f C:/x.yaml", "create cm x --from-file=/etc/hosts", "apply -k .", "get pods -o go-template-file=/x", "cp a pod:/b", "config view --raw", "proxy", "port-forward x 80", "edit deploy/x", "kubectl-evil x"])
        expect(ok(c, m), `${m}: ${c}`).toBe(false);
    }
  });
  it('blocks URL/file-list manifest tricks and local preference overrides in every mode', () => {
    expect(ok('get pods\0', 'free')).toBe(false);
    for (const mode of ['read-only', 'approval', 'free'] as const) for (const c of ['get pods -Ashttps://evil.example', 'get pods -Af/etc/passwd', 'apply -Rk/tmp', 'get pods --client_key=/etc/key', 'get pods --insecure_skip_tls_verify=true', 'get pods --tls_server_name=evil', 'get pods --as_group=admins', 'create cm test --from_file=/etc/passwd', 'get pods --cache_dir=/etc']) expect(ok(c, mode), c).toBe(false);
    for (const c of ['get pods -w=true', 'get pods -Aw', 'logs pod -pf', 'get pods --watch_only=true']) expect(ok(c), c).toBe(false);
    for (const mode of ['read-only', 'approval', 'free'] as const) for (const c of ['apply -f https://example.com/manifest.yaml,/etc/passwd', 'apply -f https://127.0.0.1/private', 'get pods --kuberc=/tmp/evil', 'get pods --cache-dir=/etc', 'get pods -o jsonpath-file=/etc/passwd']) expect(ok(c, mode), c).toBe(false);
    for (const c of ['get pods -nproduction -owide', 'get pods -lapp=web', 'logs pod -capp']) expect(ok(c), c).toBe(true);
  });
  it("allows writes in approval/free, and the remote command after -- is not inspected", () => {
    expect(ok("delete pod x -n y", "approval")).toBe(true);
    expect(ok("exec mypod -- sh -c 'ls -s /tmp'", "free")).toBe(true);
    expect(ok("get secrets -n x", "free")).toBe(true);
  });
  it("accepts a manifest only with -f -", () => {
    expect(ok("apply -f -", "approval", true)).toBe(true);
    expect(ok("apply -f -", "approval", false)).toBe(false);
    expect(ok("get pods", "approval", true)).toBe(false);
    expect(ok("apply -f -", "read-only", true)).toBe(false);
    expect(reason("apply -f -", "read-only", true)).toMatch(/read-only/);
  });
});

describe("withDefaults", () => {
  it("injects context/namespace right after the subcommand", () => {
    const p = (checkKubectl(splitArgs("exec pod -- ls"), "free") as any).parsed;
    expect(withDefaults(p, { context: "c1", namespace: "ns" })).toEqual(["exec", "--context", "c1", "--namespace", "ns", "pod", "--", "ls"]);
  });
  it("respects an explicit namespace", () => {
    const p = (checkKubectl(splitArgs("get pods -A"), "free") as any).parsed;
    expect(withDefaults(p, { namespace: "ns" })).toEqual(["get", "pods", "-A"]);
  });
});

describe("inspectKubeconfig", () => {
  const good = `apiVersion: v1
kind: Config
current-context: a
clusters: [{name: c, cluster: {server: "https://1.2.3.4:6443", certificate-authority-data: AAAA}}]
contexts: [{name: a, context: {cluster: c, user: u}}]
users: [{name: u, user: {token: abc}}]`;
  it("summarises a valid kubeconfig", () => {
    expect(inspectKubeconfig(good)).toEqual({ contexts: ["a"], currentContext: "a", servers: ["https://1.2.3.4:6443"], execCommands: [] });
  });
  it("rejects garbage and file references", () => {
    expect(() => inspectKubeconfig("hello: world")).toThrow("not a kubeconfig");
    expect(() => inspectKubeconfig(good.replace("certificate-authority-data: AAAA", "certificate-authority: /x/ca.crt"))).toThrow("--flatten");
  });
  it('rejects credential helper execution, file exposure and insecure API transport, including old stored configs', () => {
    for (const credential of ['exec: {command: sh, args: ["-c", "touch /tmp/pwn"]}', 'auth-provider: {name: gcp, config: {cmd-path: sh}}', 'tokenFile: /etc/passwd', 'token-file: /etc/passwd']) {
      const malicious = good.replace('token: abc', credential);
      expect(() => inspectKubeconfig(malicious)).toThrow();
      expect(() => runKubectl(malicious, ['get', 'pods'], { timeoutSec: 1, maxBytes: 1024 })).toThrow();
    }
    expect(() => inspectKubeconfig(good.replace('https://1.2.3.4:6443', 'http://1.2.3.4:6443'))).toThrow('HTTPS');
    expect(() => inspectKubeconfig(good.replace('certificate-authority-data: AAAA', 'insecure-skip-tls-verify: true'))).toThrow('verification');
    expect(() => inspectKubeconfig(good.replace('certificate-authority-data: AAAA', 'proxy-url: https://evil.example'))).toThrow('proxy-url');
  });
  it('isolates kubectl from inherited application secrets, home credentials and preferences', () => {
    const env = kubectlEnvironment('/private/tmp', '/private/tmp/config');
    expect(env.HOME).toBe('/private/tmp');
    expect(env.KUBECONFIG).toBe('/private/tmp/config');
    expect(env.KUBECTL_KUBERC).toBe('false');
    expect(env.KUBERC).toBe('off');
    expect(Object.keys(env)).not.toContain('AWS_SECRET_ACCESS_KEY');
    expect(Object.keys(env)).not.toContain('AUTH_URL');
  });
});
