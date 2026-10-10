// Secrets (class `secret`), spec section 9.5.1. Patterns are checked in the listed order
// (Anthropic before OpenAI); a later pattern never reports a span an earlier one already claimed.

import type { Severity } from "../../types.js";
import {
  type DetectOptions,
  type DetectorMatch,
  dropOverlaps,
  isPlaceholder,
  keyedValues,
  looksLikeUrlOrPath,
  shannonEntropy,
} from "./common.js";

interface Pattern {
  kind: string;
  label: string;
  re: RegExp;
  severity: Severity;
  /** Capture group holding the secret value (default: whole match). */
  group?: number;
  prefix?: (value: string) => string | undefined;
}

const firstMatch = (re: RegExp) => (v: string) => re.exec(v)?.[0];

const PATTERNS: Pattern[] = [
  { kind: "aws-access-key-id", label: "AWS access key ID", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, severity: "critical", prefix: (v) => v.slice(0, 4) },
  {
    kind: "aws-secret-key",
    label: "AWS secret access key",
    re: /aws_secret_access_key["']?\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi,
    group: 1,
    severity: "critical",
  },
  { kind: "github-token", label: "GitHub token", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b/g, severity: "critical", prefix: (v) => v.slice(0, 4) },
  { kind: "github-pat", label: "GitHub fine-grained token", re: /\bgithub_pat_[A-Za-z0-9_]{50,255}\b/g, severity: "critical", prefix: () => "github_pat_" },
  {
    kind: "stripe-secret-key",
    label: "Stripe secret key",
    re: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,255}\b/g,
    severity: "critical",
    prefix: firstMatch(/^(?:sk|rk)_(?:live|test)_/),
  },
  { kind: "anthropic-key", label: "Anthropic key", re: /\bsk-ant-[A-Za-z0-9_-]{20,255}\b/g, severity: "critical", prefix: () => "sk-ant-" },
  {
    kind: "openai-key",
    label: "OpenAI key",
    re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,255}\b/g,
    severity: "critical",
    prefix: firstMatch(/^sk-(?:proj-|svcacct-|admin-)?/),
  },
  { kind: "slack-token", label: "Slack token", re: /\bxox[abposr]-[A-Za-z0-9-]{10,255}\b/g, severity: "critical", prefix: (v) => v.slice(0, 5) },
  {
    kind: "slack-webhook",
    label: "Slack webhook URL",
    re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]{1,255}/g,
    severity: "critical",
    prefix: () => "https://hooks.slack.com/services/",
  },
  { kind: "sendgrid-key", label: "SendGrid key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, severity: "critical", prefix: () => "SG." },
  { kind: "google-api-key", label: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, severity: "medium", prefix: () => "AIza" },
  {
    kind: "private-key",
    label: "Private key",
    // (?!…): a header already followed by "…" is SECOR's own redacted form, not a key (keeps redaction idempotent).
    // The lookahead requires key material after the header, so a bare header in a test assertion or a scanner
    // allowlist is not a key.
    re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----(?!…)(?=[\s\S]{0,120}?[A-Za-z0-9+/]{40})(?:[\s\S]{0,8192}?-----END [A-Z ]{0,40}PRIVATE KEY(?: BLOCK)?-----)?/g,
    severity: "critical",
    prefix: firstMatch(/^-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----/),
  },
  { kind: "supabase-secret-key", label: "Supabase secret key", re: /\bsb_secret_[A-Za-z0-9_-]{20,255}\b/g, severity: "critical", prefix: () => "sb_secret_" },
];

/** Anchored forms of the specific patterns: a value one of them recognises is never re-reported by the generic rule. */
const OWNED_BY_SPECIFIC = PATTERNS.filter((p) => !p.group).map((p) => new RegExp(`^(?:${p.re.source})$`));

const JWT = /\beyJ[A-Za-z0-9_-]{5,2048}\.eyJ[A-Za-z0-9_-]{5,4096}\.[A-Za-z0-9_-]{10,2048}\b/g;
const GENERIC_KEY = /secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret/i;
// Mapbox public tokens ("pk.") are browser tokens by design; Mapbox secret tokens start with "sk." (DECISIONS.md).
const PUBLIC_BY_DESIGN = /^(?:pk_(?:live|test)_|sb_publishable_|phc_|pk\.eyJ)/;
const SENTRY_DSN = /^https:\/\/[^@\s]+@o\d+\.ingest\.(?:us\.)?sentry\.io\/\d+$/;

function jwtPayload(token: string): Record<string, unknown> | null {
  const payload = token.split(".")[1];
  if (!payload) return null;
  try {
    const json = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as unknown;
    return json && typeof json === "object" ? (json as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

export function jwtRole(token: string): string | null {
  const role = jwtPayload(token)?.role;
  return typeof role === "string" ? role : null;
}

/** Supabase's documented local-development keys (`iss: "supabase-demo"`) are published for every `supabase start`. */
function isSupabaseDemoKey(token: string): boolean {
  return jwtPayload(token)?.iss === "supabase-demo";
}

/**
 * Share of characters that sit in ascending runs of three or more ("abcd", "1234"): test vectors such as
 * "abcd1234efgh5678" are built this way, random secrets are not.
 */
export function sequentialShare(v: string): number {
  let inRuns = 0;
  let run = 1;
  for (let i = 1; i <= v.length; i++) {
    if (i < v.length && v.charCodeAt(i) === v.charCodeAt(i - 1) + 1) {
      run++;
      continue;
    }
    if (run >= 3) inRuns += run;
    run = 1;
  }
  return v.length ? inRuns / v.length : 0;
}

/**
 * Values the generic rule should not treat as secrets (DECISIONS.md): non-ASCII text (translations), sequential
 * test vectors, URNs,
 * Ethereum addresses (public), a value equal to its key or shaped like an env var name, and word-like strings
 * ("upstream-refresh-token", "Zwei-Faktor-Token") used as test dummies and labels.
 */
export function looksLikeNonSecret(key: string, v: string): boolean {
  if (!/^[\x21-\x7e]+$/.test(v)) return true;
  if (sequentialShare(v) >= 0.75) return true;
  if (/^urn:/i.test(v) || /^0x[0-9a-fA-F]{40}$/.test(v)) return true;
  const norm = (x: string) => x.toLowerCase().replace(/[^a-z0-9]/g, "");
  if (norm(v) === norm(key)) return true;
  if (/^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$/.test(v)) return true;
  return /^[A-Za-z]{2,}(?:[-_.](?:[A-Za-z]{2,}|[0-9]{1,4}))+$/.test(v);
}

/** True when an AIza key sits in a Firebase web config: its enclosing object (or, outside any object, the file) names authDomain or projectId. */
function inFirebaseConfig(text: string, start: number): boolean {
  let depth = 0;
  let open = -1;
  for (let i = start - 1; i >= 0 && start - i < 4000; i--) {
    const c = text[i];
    if (c === "}") depth++;
    else if (c === "{") {
      if (depth === 0) {
        open = i;
        break;
      }
      depth--;
    }
  }
  let region: string;
  if (open >= 0) {
    let d = 0;
    let close = text.length;
    for (let i = open; i < text.length && i - open < 8000; i++) {
      if (text[i] === "{") d++;
      else if (text[i] === "}") {
        d--;
        if (d === 0) {
          close = i;
          break;
        }
      }
    }
    region = text.slice(open, close + 1);
  } else {
    region = text;
  }
  return /auth_?domain|project_?id/i.test(region);
}

export function isPublicByDesign(value: string): boolean {
  if (PUBLIC_BY_DESIGN.test(value)) return true;
  if (SENTRY_DSN.test(value)) return true;
  if (/^eyJ/.test(value) && (jwtRole(value) === "anon" || isSupabaseDemoKey(value))) return true;
  return false;
}

export function detectSecrets(text: string, opts: DetectOptions = {}): DetectorMatch[] {
  const found: DetectorMatch[] = [];
  for (const p of PATTERNS) {
    p.re.lastIndex = 0;
    for (let m = p.re.exec(text); m; m = p.re.exec(text)) {
      const value = p.group ? m[p.group]! : m[0];
      const valueStart = p.group ? m[0].lastIndexOf(value) : 0;
      if (isPlaceholder(value)) continue;
      let severity = p.severity;
      if (p.kind === "stripe-secret-key" && /_test_/.test(value)) severity = "low";
      if (p.kind === "google-api-key" && inFirebaseConfig(text, m.index)) continue;
      found.push({
        class: "secret",
        kind: p.kind,
        label: p.label,
        start: m.index,
        end: m.index + m[0].length,
        value,
        valueStart,
        severity,
        prefix: p.prefix?.(value),
      });
    }
  }
  JWT.lastIndex = 0;
  for (let m = JWT.exec(text); m; m = JWT.exec(text)) {
    if (jwtRole(m[0]) !== "service_role" || isSupabaseDemoKey(m[0])) continue;
    found.push({
      class: "secret",
      kind: "supabase-service-role-jwt",
      label: "Supabase service-role key",
      start: m.index,
      end: m.index + m[0].length,
      value: m[0],
      valueStart: 0,
      severity: "critical",
      prefix: "eyJ",
    });
  }
  for (const kv of keyedValues(text, opts)) {
    if (!GENERIC_KEY.test(kv.key)) continue;
    const v = kv.value;
    if (v.length < 16 || /\s/.test(v)) continue;
    if (isPlaceholder(v) || isPublicByDesign(v) || looksLikeUrlOrPath(v) || looksLikeNonSecret(kv.key, v)) continue;
    // Specific patterns own their values, including ones they suppress (Firebase config apiKey).
    if (OWNED_BY_SPECIFIC.some((re) => re.test(v))) continue;
    if (shannonEntropy(v) < 3.5) continue;
    const start = kv.start + kv.valueStart;
    found.push({
      class: "secret",
      kind: "generic-secret",
      label: `Secret assigned to "${kv.key}"`,
      start,
      end: start + v.length,
      value: v,
      valueStart: 0,
      severity: "high",
    });
  }
  return dropOverlaps(found);
}
