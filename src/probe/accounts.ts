// Optional test accounts for the authenticated checks (spec 9A.4). The developer supplies two test
// accounts they created on staging, as ready-made session headers/cookies. These are NEVER logged,
// never written to disk by Probe, and never placed in evidence.

import { readFileSync } from "node:fs";
import { ProbeRefusal } from "./types.js";

export interface TestAccount {
  headers: Record<string, string>;
  cookies: Record<string, string>;
}

export interface TestAccounts {
  a: TestAccount;
  b: TestAccount;
}

function normAccount(raw: unknown, which: string): TestAccount {
  if (!raw || typeof raw !== "object") throw new ProbeRefusal("bad-accounts", `accounts file: "${which}" must be an object with headers and/or cookies`);
  const obj = raw as Record<string, unknown>;
  const headers: Record<string, string> = {};
  const cookies: Record<string, string> = {};
  if (obj.headers && typeof obj.headers === "object") {
    for (const [k, v] of Object.entries(obj.headers as Record<string, unknown>)) if (typeof v === "string") headers[k] = v;
  }
  if (obj.cookies && typeof obj.cookies === "object") {
    for (const [k, v] of Object.entries(obj.cookies as Record<string, unknown>)) if (typeof v === "string") cookies[k] = v;
  }
  if (Object.keys(headers).length === 0 && Object.keys(cookies).length === 0) {
    throw new ProbeRefusal("bad-accounts", `accounts file: "${which}" has no headers or cookies`);
  }
  return { headers, cookies };
}

/** Build the request headers for an account (Authorization etc. + a Cookie header). */
export function accountHeaders(account: TestAccount): Record<string, string> {
  const headers = { ...account.headers };
  const cookie = Object.entries(account.cookies)
    .map(([k, v]) => `${k}=${v}`)
    .join("; ");
  if (cookie) headers.cookie = cookie;
  return headers;
}

export function loadAccounts(path: string): TestAccounts {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new ProbeRefusal("bad-accounts", `accounts file ${path}: ${(e as Error).message}`);
  }
  const obj = (raw ?? {}) as Record<string, unknown>;
  const a = obj.a ?? obj.accountA ?? obj.A;
  const b = obj.b ?? obj.accountB ?? obj.B;
  if (a === undefined || b === undefined) throw new ProbeRefusal("bad-accounts", `accounts file must define two accounts "a" and "b" (or accountA / accountB)`);
  return { a: normAccount(a, "a"), b: normAccount(b, "b") };
}
