// Connect validation targets (spec 14.3): hook catch rate for verbatim planted secrets ≥ 95%, and false blocks on
// legitimate calls < 2%. Planted values are generated at run time; the legitimate corpus is full of look-alikes
// (hashes, IDs, base64, ARNs) that must pass.

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runHook } from "../../src/connect/hooks.js";
import { FAKE } from "../helpers/fixtures.js";
import { type TempEnv, tempEnv } from "./helpers.js";

let env: TempEnv;
beforeAll(() => {
  env = tempEnv();
  mkdirSync(env.secorHome, { recursive: true });
  // Every class forbidden (the default), unmanaged servers continue with the default scope.
  writeFileSync(join(env.secorHome, "scopes.yaml"), "version: 1\ndefaults:\n  unvetted: pass\n  onViolation: ask\n");
});
afterAll(() => env.restore());

const call = (tool: string, input: unknown) =>
  JSON.stringify({ session_id: "val-1", cwd: env.project, hook_event_name: "PreToolUse", tool_name: `mcp__notes__${tool}`, tool_input: input, tool_use_id: "t" });

async function decision(tool: string, input: unknown): Promise<"pass" | "ask" | "deny"> {
  const out = (await runHook("pre", call(tool, input))).trim();
  if (!out) return "pass";
  return (JSON.parse(out) as { hookSpecificOutput: { permissionDecision: "ask" | "deny" } }).hookSpecificOutput.permissionDecision;
}

const PLANTED: Record<string, string> = {
  aws: FAKE.AWS_ACCESS_KEY,
  awsSecret: `aws_secret_access_key = ${FAKE.AWS_SECRET}`,
  github: FAKE.GITHUB,
  stripe: FAKE.STRIPE_LIVE,
  anthropic: FAKE.ANTHROPIC,
  openai: FAKE.OPENAI,
  slack: FAKE.SLACK,
  slackWebhook: FAKE.SLACK_WEBHOOK,
  sendgrid: FAKE.SENDGRID,
  google: FAKE.GOOGLE,
  supabaseSecret: FAKE.SUPABASE_SECRET,
  serviceRole: FAKE.SERVICE_ROLE_JWT,
  privateKey: FAKE.PRIVATE_KEY,
  generic: `client_secret = "${FAKE.GENERIC}"`,
  dbUrl: `postgres://app:${FAKE.DB_PASSWORD}@db.prod.acme-corp.net:5432/app`,
  password: `"password": "${FAKE.DB_PASSWORD}"`,
  email: "jane.doe@acme-corp.io",
  phone: "+14155550123",
  card: "4111 1111 1111 1111",
  iban: "DE89370400440532013000",
};

const SHAPES: ((v: string) => [string, unknown])[] = [
  (v) => ["create_note", { title: "Deploy notes", body: v }],
  (v) => ["create_note", { title: "Config", body: `Here is the prod config for the team:\n\n${v}\n\nThanks!` }],
  (v) => ["update_page", { page: { id: "p1", blocks: [{ type: "text", text: v }] } }],
  (v) => ["search", { query: `find where ${v} is used`, limit: 10 }],
  (v) => ["send_message", { channel: "#ops", messages: ["fyi", `${v}`, "ok"] }],
];

const LEGIT: [string, unknown][] = [];
const hex = (n: number, seed: number) => Array.from({ length: n }, (_, i) => "0123456789abcdef"[(seed * 31 + i * 17 + ((i * i) % 7)) % 16]).join("");
for (let i = 0; i < 40; i++) {
  LEGIT.push(["search_code", { query: `function handle${i}Request`, repo: `acme/service-${i}`, ref: hex(40, i) }]);
  LEGIT.push(["create_issue", { title: `Fix flaky test #${1000 + i}`, body: `Steps:\n1. Run \`npm test -- --grep ${i}\`\n2. See failure in build ${hex(12, i)}`, labels: ["bug", "ci"] }]);
  LEGIT.push(["get_object", { id: `cus_${hex(14, i + 3)}`, payment_intent: `pi_${hex(24, i + 5)}`, request_id: `req_${hex(16, i + 7)}` }]);
  LEGIT.push(["read_file", { path: `src/modules/feature-${i}/index.ts`, sha256: hex(64, i + 9), uuid: `${hex(8, i)}-${hex(4, i + 1)}-4${hex(3, i + 2)}-a${hex(3, i + 3)}-${hex(12, i + 4)}` }]);
  LEGIT.push(["run_query", { sql: `SELECT id, name FROM orders WHERE created_at > '2026-0${(i % 9) + 1}-01' LIMIT ${i + 1}` }]);
}
for (let i = 0; i < 10; i++) {
  LEGIT.push(["upload_image", { name: `chart-${i}.png`, data: Buffer.from(hex(300, i)).toString("base64") }]);
  LEGIT.push(["describe_resource", { arn: `arn:aws:s3:::acme-logs-${i}/2026/10/${i}`, region: "eu-west-1", bucket_url: `https://acme-logs-${i}.s3.amazonaws.com/` }]);
  LEGIT.push(["save_note", { text: `Order #${88000 + i} shipped on 2026-10-${10 + i}. Tracking 1Z${hex(16, i).toUpperCase()}. Version 4.${i}.2.` }]);
  LEGIT.push(["set_config", { config: { apiBase: "https://api.acme.dev/v2", timeoutMs: 30000 + i, retries: 3, tokenTtlSeconds: 3600, features: ["a", "b"] } }]);
  LEGIT.push(["post_snippet", { language: "ts", code: `const token = req.headers.authorization?.split(" ")[1];\nif (!token) return res.status(401).end();\nconst apiKey = process.env.OPENAI_API_KEY;` }]);
}

describe("Connect validation (spec 14.3)", () => {
  it("catches ≥ 95% of verbatim planted secrets, credentials and personal data", async () => {
    let caught = 0;
    const missed: string[] = [];
    let total = 0;
    for (const [kind, value] of Object.entries(PLANTED)) {
      for (const shape of SHAPES) {
        const [tool, input] = shape(value);
        total++;
        const d = await decision(tool, input);
        if (d !== "pass") caught++;
        else missed.push(`${kind} in ${tool}`);
      }
    }
    const rate = caught / total;
    console.log(`hook catch rate: ${caught}/${total} = ${(rate * 100).toFixed(1)}%${missed.length ? ` (missed: ${missed.join(", ")})` : ""}`);
    expect(rate).toBeGreaterThanOrEqual(0.95);
  });

  it("false blocks on legitimate calls < 2%", async () => {
    let blocked = 0;
    const which: string[] = [];
    for (const [tool, input] of LEGIT) {
      const d = await decision(tool, input);
      if (d !== "pass") {
        blocked++;
        which.push(`${tool}: ${JSON.stringify(input).slice(0, 80)}`);
      }
    }
    const rate = blocked / LEGIT.length;
    console.log(`hook false blocks: ${blocked}/${LEGIT.length} = ${(rate * 100).toFixed(1)}%${which.length ? `\n  ${which.join("\n  ")}` : ""}`);
    expect(rate).toBeLessThan(0.02);
  });
});
