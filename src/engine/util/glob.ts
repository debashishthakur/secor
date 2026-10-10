// Glob matching for config excludes, scope paths and confidential paths.
// Supported: "**" (any number of segments), "*", "?", "[...]" classes, "{a,b}" alternatives.
// A pattern without "/" matches the basename at any depth (gitignore-style); a trailing "/"
// means "everything under this directory". See DECISIONS.md.

const cache = new Map<string, RegExp>();

export function globToRegExp(pattern: string): RegExp {
  const cached = cache.get(pattern);
  if (cached) return cached;
  let p = pattern.replace(/\\/g, "/");
  if (p.startsWith("./")) p = p.slice(2);
  const dirOnly = p.endsWith("/");
  const trimmed = dirOnly ? p.slice(0, -1) : p;
  const anchored = trimmed.includes("/");
  let body = translate(dirOnly ? `${trimmed}/**` : trimmed);
  if (!anchored) body = `(?:.*/)?${body}`;
  const re = new RegExp(`^${body}$`);
  cache.set(pattern, re);
  return re;
}

/** Translate a glob body (no anchoring) to a regex source. */
export function translateGlob(p: string): string {
  return translate(p);
}

function translate(p: string): string {
  let out = "";
  let i = 0;
  while (i < p.length) {
    const c = p[i]!;
    if (c === "*") {
      if (p[i + 1] === "*") {
        const atStart = i === 0 || p[i - 1] === "/";
        const atEnd = i + 2 === p.length || p[i + 2] === "/";
        if (atStart && atEnd) {
          if (i + 2 === p.length) {
            out += ".*";
            i += 2;
          } else {
            out += "(?:.*/)?";
            i += 3;
          }
          continue;
        }
        out += "[^/]*";
        i += 2;
        continue;
      }
      out += "[^/]*";
      i += 1;
      continue;
    }
    if (c === "?") {
      out += "[^/]";
      i += 1;
      continue;
    }
    if (c === "[") {
      const close = p.indexOf("]", i + 2);
      if (close > i) {
        let cls = p.slice(i + 1, close).replace(/\\/g, "\\\\");
        if (cls.startsWith("!")) cls = `^${cls.slice(1)}`;
        out += `[${cls}]`;
        i = close + 1;
        continue;
      }
    }
    if (c === "{") {
      const close = p.indexOf("}", i);
      if (close > i) {
        const alts = p.slice(i + 1, close).split(",").map(translate);
        out += `(?:${alts.join("|")})`;
        i = close + 1;
        continue;
      }
    }
    out += c.replace(/[.+^$()|\\{}[\]]/g, "\\$&");
    i += 1;
  }
  return out;
}

export function matchesGlob(path: string, pattern: string): boolean {
  return globToRegExp(pattern).test(path);
}

export function matchesAny(path: string, patterns: readonly string[]): boolean {
  for (const pat of patterns) if (matchesGlob(path, pat)) return true;
  return false;
}
