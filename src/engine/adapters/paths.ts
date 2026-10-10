// Path normalisation for HTTP entry points. Params are written ":name" (spec section 7).

export function joinPaths(prefix: string, path: string): string {
  if (!prefix) return path || "/";
  if (!path || path === "/") return prefix.startsWith("{") ? prefix : prefix.replace(/\/+$/, "") || "/";
  if (path.startsWith("{")) return `${prefix.replace(/\/+$/, "")}/${path}`;
  return `${prefix.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`.replace(/\/{2,}/g, "/");
}

/** Express paths: drop regex constraints (`:id(\\d+)` → `:id`), Express 5 braces (`{/:x}` → `/:x?`), duplicate slashes. */
export function normaliseExpressPath(p: string): string {
  let s = p.trim();
  s = s.replace(/(:\w+)\([^)]*\)/g, "$1");
  s = s.replace(/\{(\/?:\w+)\}/g, "$1?");
  s = s.replace(/\*(\w+)/g, ":$1*");
  s = s.replace(/\/{2,}/g, "/");
  if (s !== "*" && !s.startsWith("/") && !s.startsWith("*")) s = `/${s}`;
  return s;
}

/** FastAPI paths: `{id}` → `:id`, `{path:path}` → `:path`. */
export function normaliseFastapiPath(p: string): string {
  let s = p.trim().replace(/\{(\w+)(?::\w+)?\}/g, ":$1");
  if (!s.startsWith("/")) s = `/${s}`;
  return s.replace(/\/{2,}/g, "/");
}

/**
 * Next.js file-system path for a route segment list (relative to app/ or pages/):
 * drop route groups `(x)` and parallel slots `@x`; `[id]` → `:id`, `[...slug]` → `:slug*`, `[[...slug]]` → `:slug*?`.
 */
export function nextSegmentsToPath(segments: readonly string[]): string {
  const out: string[] = [];
  for (const seg of segments) {
    if (!seg) continue;
    if (/^\(.*\)$/.test(seg) || seg.startsWith("@")) continue;
    let m = /^\[\[\.\.\.(\w+)\]\]$/.exec(seg);
    if (m) {
      out.push(`:${m[1]}*?`);
      continue;
    }
    m = /^\[\.\.\.(\w+)\]$/.exec(seg);
    if (m) {
      out.push(`:${m[1]}*`);
      continue;
    }
    m = /^\[(\w+)\]$/.exec(seg);
    if (m) {
      out.push(`:${m[1]}`);
      continue;
    }
    out.push(seg);
  }
  return `/${out.join("/")}`;
}

/** Segment-wise path equality where any ":param" matches any ":param" (names may differ). */
export function samePath(a: string, b: string): boolean {
  const sa = a.split("/").filter(Boolean);
  const sb = b.split("/").filter(Boolean);
  if (sa.length !== sb.length) return false;
  return sa.every((s, i) => {
    const t = sb[i]!;
    if (s.startsWith(":") && t.startsWith(":")) return s.endsWith("*") === t.endsWith("*") && s.endsWith("?") === t.endsWith("?");
    return s === t;
  });
}
