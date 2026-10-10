import { describe, expect, it } from "vitest";
import { appendConsentRecord, detectOperator, obtainConsent } from "../../src/probe/consent.js";
import { ProbeRefusal } from "../../src/probe/types.js";
import { nonTtyIO, scriptedIO, tempHome } from "../probe/helpers.js";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const code = async (fn: () => Promise<unknown>): Promise<string> => {
  try {
    await fn();
    return "<ok>";
  } catch (e) {
    return e instanceof ProbeRefusal ? e.code : `<${(e as Error).name}>`;
  }
};

describe("obtainConsent", () => {
  it("accepts the flag + staging host + y confirmation", async () => {
    const io = scriptedIO(["y"]);
    await obtainConsent(io, { host: "staging.myapp.com", iOwnThisTarget: true, plan: ["GET /"] });
    expect(io.output.join("\n")).toContain("GET /");
  });

  it("refuses a non-TTY even with the flag (no unattended mode)", async () => {
    expect(await code(() => obtainConsent(nonTtyIO(), { host: "localhost", iOwnThisTarget: true, plan: ["GET /"] }))).toBe("no-confirmation-unattended");
  });

  it("refuses a non-TTY with no flag", async () => {
    expect(await code(() => obtainConsent(nonTtyIO(), { host: "localhost", iOwnThisTarget: false, plan: ["GET /"] }))).toBe("no-consent");
  });

  it("accepts typing the host instead of the flag", async () => {
    const io = scriptedIO(["staging.myapp.com", "y"]);
    await obtainConsent(io, { host: "staging.myapp.com", iOwnThisTarget: false, plan: ["GET /"] });
  });

  it("refuses when the typed host does not match", async () => {
    const io = scriptedIO(["wrong.com", "y"]);
    expect(await code(() => obtainConsent(io, { host: "staging.myapp.com", iOwnThisTarget: false, plan: ["GET /"] }))).toBe("ownership-not-confirmed");
  });

  it("requires extra confirmation for a non-staging host", async () => {
    const declined = scriptedIO(["nope", "y"]);
    expect(await code(() => obtainConsent(declined, { host: "api.myapp.com", iOwnThisTarget: true, plan: ["GET /"] }))).toBe("not-staging");
    const ok = scriptedIO(["yes, not production", "y"]);
    await obtainConsent(ok, { host: "api.myapp.com", iOwnThisTarget: true, plan: ["GET /"] });
  });

  it("refuses when the final confirmation is not y", async () => {
    const io = scriptedIO(["n"]);
    expect(await code(() => obtainConsent(io, { host: "localhost", iOwnThisTarget: true, plan: ["GET /"] }))).toBe("declined");
  });
});

describe("consent log + operator", () => {
  it("detectOperator returns a non-empty string", () => {
    expect(detectOperator({ USER: "alice" }).length).toBeGreaterThan(0);
  });

  it("appends a record to probe-runs.jsonl with the right shape", () => {
    const h = tempHome();
    try {
      const rec = appendConsentRecord("http://localhost:3000/", "local", new Date("2026-10-10T00:00:00Z"), { USER: "alice" });
      expect(rec).toMatchObject({ target: "http://localhost:3000/", method: "local", operator: expect.any(String), rulesVersion: "1.0.0" });
      const text = readFileSync(join(h.secorHome, "probe-runs.jsonl"), "utf8").trim();
      expect(JSON.parse(text)).toMatchObject({ target: "http://localhost:3000/", method: "local" });
    } finally {
      h.restore();
    }
  });
});
