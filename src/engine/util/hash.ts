import { createHash } from "node:crypto";

export function sha256Hex(text: string): string {
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** JSON with object keys sorted recursively, no whitespace. Used for tool hashes and hook input sizing. */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value && typeof value === "object") {
    // Null prototype: a "__proto__" key from untrusted JSON stays an ordinary key and is hashed.
    const out: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const v = (value as Record<string, unknown>)[key];
      if (v !== undefined) out[key] = sortKeys(v);
    }
    return out;
  }
  return value;
}
