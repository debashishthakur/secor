// Redaction (spec 8.6): exact forms, evidence flattening/truncation, deep redaction.

import { describe, expect, it } from "vitest";
import { evidence, redact, redactDeep, redactSecretValue } from "../../src/engine/redact.js";
import { FAKE, PEM_HEADER } from "../helpers/fixtures.js";

describe("secret redaction keeps the known prefix, else 2 chars, then …, then the last 4", () => {
  const cases: [string, string][] = [
    [FAKE.STRIPE_LIVE, "sk_live_"],
    [FAKE.STRIPE_TEST, "sk_test_"],
    [FAKE.GITHUB, "ghp_"],
    [FAKE.AWS_ACCESS_KEY, "AKIA"],
    [FAKE.ANTHROPIC, "sk-ant-"],
    [FAKE.OPENAI, "sk-proj-"],
    [FAKE.SLACK, "xoxb-"],
    [FAKE.SUPABASE_SECRET, "sb_secret_"],
    [FAKE.SENDGRID, "SG."],
    [FAKE.SERVICE_ROLE_JWT, "eyJ"],
  ];
  for (const [value, prefix] of cases) {
    it(prefix, () => {
      const out = redact(`key = "${value}"`);
      expect(out).toBe(`key = "${prefix}…${value.slice(-4)}"`);
      expect(out).not.toContain(value);
    });
  }

  it("generic secrets keep the first 2 characters", () => {
    expect(redact(`client_secret = "${FAKE.GENERIC}"`)).toBe(`client_secret = "${FAKE.GENERIC.slice(0, 2)}…${FAKE.GENERIC.slice(-4)}"`);
  });

  it("values under 12 characters become [REDACTED]", () => {
    expect(redactSecretValue("abcdefghijk")).toBe("[REDACTED]");
    expect(redactSecretValue("abcdefghijkl")).toBe("ab…ijkl");
  });

  it("private keys are replaced as a whole block", () => {
    const out = redact(`k = \`${FAKE.PRIVATE_KEY}\``);
    expect(out).not.toMatch(/[A-Za-z0-9+/]{40,}/);
    expect(out).toContain(`${PEM_HEADER}…`);
  });

  it("is idempotent: redacting redacted text changes nothing", () => {
    const text = [
      ...Object.values(FAKE).map((v) => `key = "${v}"`),
      FAKE.PRIVATE_KEY,
      `postgres://app:${FAKE.DB_PASSWORD}@db.prod.example-corp.net/app`,
      "mail jane.doe@acme.io, call +14155550123, card 4111 1111 1111 1111, iban DE89370400440532013000",
    ].join("\n");
    const once = redact(text);
    expect(redact(once)).toBe(once);
    expect(redact(redact(once))).toBe(once);
  });

  it("AWS secret key with context redacts the value only", () => {
    const out = redact(`aws_secret_access_key = ${FAKE.AWS_SECRET}`);
    expect(out).toBe(`aws_secret_access_key = ${FAKE.AWS_SECRET.slice(0, 2)}…${FAKE.AWS_SECRET.slice(-4)}`);
  });
});

describe("credentials and personal data", () => {
  it("db URL password and password literals", () => {
    expect(redact(`postgres://app:${FAKE.DB_PASSWORD}@db.prod.example-corp.net/app`)).toBe("postgres://app:[REDACTED]@db.prod.example-corp.net/app");
    expect(redact(`const password = "hunter2hunter2"`)).toBe(`const password = "[REDACTED]"`);
  });

  it("email, phone, card, IBAN", () => {
    expect(redact("mail jane.doe@acme.io now")).toBe("mail j***@acme.io now");
    expect(redact("call +14155550123")).toBe("call [PHONE …23]");
    expect(redact("card 4111 1111 1111 1111.")).toBe("card [CARD …1111].");
    expect(redact("iban DE89370400440532013000")).toBe("iban [IBAN …3000]");
  });

  it("leaves ordinary code untouched", () => {
    const code = `app.get("/users/:id", requireAuth, async (req, res) => res.json(await db.user.findUnique({ where: { id: req.params.id } })));`;
    expect(redact(code)).toBe(code);
  });
});

describe("evidence", () => {
  it("is one line with ⏎ for newlines", () => {
    expect(evidence("a\nb\r\nc")).toBe("a⏎b⏎c");
  });

  it("truncates to 200 characters with …", () => {
    const e = evidence("x".repeat(500));
    expect([...e]).toHaveLength(200);
    expect(e.endsWith("…")).toBe(true);
  });

  it("redacts before truncating, so a secret across the 200-char boundary never leaks", () => {
    const text = `${"y".repeat(190)} key="${FAKE.OPENAI}"`;
    const e = evidence(text);
    expect(e).not.toContain(FAKE.OPENAI.slice(0, 20));
    expect(e).not.toContain(FAKE.OPENAI.slice(8, 30));
  });
});

describe("redactDeep", () => {
  it("redacts strings at any depth and keeps structure", () => {
    const v = { a: [`token ${FAKE.GITHUB}`, 3, null, { b: `mail a.b@c.de` }], n: 1, t: true };
    const out = redactDeep(v);
    expect(JSON.stringify(out)).not.toContain(FAKE.GITHUB);
    expect(out).toEqual({ a: [`token ghp_…${FAKE.GITHUB.slice(-4)}`, 3, null, { b: "mail a***@c.de" }], n: 1, t: true });
  });

  it("keeps a __proto__ key from untrusted JSON as data", () => {
    const parsed = JSON.parse(`{"__proto__": {"x": "${FAKE.GITHUB}"}, "y": 1}`) as Record<string, unknown>;
    const out = redactDeep(parsed);
    expect(Object.keys(out)).toEqual(["__proto__", "y"]);
    expect(JSON.stringify(out)).not.toContain(FAKE.GITHUB);
    expect(({} as Record<string, unknown>).x).toBeUndefined();
  });
});
