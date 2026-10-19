import { describe, expect, it } from "vitest";
import { checkKubectl, inspectKubeconfig, splitArgs, withDefaults } from "../src/k8s/kubectl.js";

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
});
