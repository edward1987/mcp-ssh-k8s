import { createServer } from "node:net";
import { describe, expect, it } from "vitest";
import { probe } from "../src/health.js";

describe("probe", () => {
  it("detects an open and a closed port", async () => {
    const srv = createServer((s) => s.destroy());
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as any).port;
    expect((await probe("127.0.0.1", port)).online).toBe(true);
    await new Promise((r) => srv.close(r));
    expect((await probe("127.0.0.1", port)).online).toBe(false);
  });
});
