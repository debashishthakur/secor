// Version parsing and ordering for dependency advisories (core/vulnerable-dependency): semver 2.0.0 for npm
// and PEP 440 for PyPI. Comparators return null when either version cannot be parsed, so callers never act
// on a guess.

export type VersionEcosystem = "npm" | "PyPI";

// ---------------------------------------------------------------- semver (npm)

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  /** Pre-release identifiers: numbers for numeric identifiers, strings otherwise. Empty for a release. */
  pre: (number | string)[];
}

const SEMVER = /^[v=]?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

export function parseSemver(version: string): SemVer | null {
  const m = SEMVER.exec(version.trim());
  if (!m) return null;
  const nums = [m[1]!, m[2]!, m[3]!].map(Number);
  if (nums.some((n) => !Number.isSafeInteger(n))) return null;
  const pre = m[4] ? m[4].split(".").map((p) => (/^\d+$/.test(p) ? Number(p) : p)) : [];
  return { major: nums[0]!, minor: nums[1]!, patch: nums[2]!, pre };
}

function cmp<T extends number | string>(a: T, b: T): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Semver precedence (build metadata ignored). Null when either side is not a valid semver version. */
export function compareSemver(a: string, b: string): number | null {
  const x = parseSemver(a);
  const y = parseSemver(b);
  if (!x || !y) return null;
  const core = cmp(x.major, y.major) || cmp(x.minor, y.minor) || cmp(x.patch, y.patch);
  if (core) return core;
  // A release ranks above any of its pre-releases.
  if (!x.pre.length || !y.pre.length) return cmp(y.pre.length, x.pre.length);
  for (let i = 0; i < Math.max(x.pre.length, y.pre.length); i++) {
    const p = x.pre[i];
    const q = y.pre[i];
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    if (typeof p === "number" && typeof q === "number") {
      if (p !== q) return cmp(p, q);
    } else if (typeof p === "number") return -1;
    else if (typeof q === "number") return 1;
    else if (p !== q) return cmp(p, q);
  }
  return 0;
}

// ---------------------------------------------------------------- PEP 440 (PyPI)

export interface Pep440 {
  epoch: number;
  /** Release segment with trailing zeros removed (1.0.0 == 1). */
  release: number[];
  /** Pre-release as [rank, n] (a=0, b=1, rc=2), or ±Infinity when absent (see key()). */
  pre: [number, number] | null;
  post: number | null;
  dev: number | null;
  local: (number | string)[] | null;
}

// The canonical PEP 440 pattern (packaging.version.VERSION_PATTERN), case-insensitive.
const PEP440 =
  /^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(alpha|a|beta|b|preview|pre|c|rc)[-_.]?(\d+)?)?(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d+)?)?(?:[-_.]?(dev)[-_.]?(\d+)?)?(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$/i;

const PRE_RANK: Record<string, number> = { a: 0, alpha: 0, b: 1, beta: 1, c: 2, rc: 2, pre: 2, preview: 2 };

export function parsePep440(version: string): Pep440 | null {
  const m = PEP440.exec(version.trim());
  if (!m) return null;
  const release = m[2]!.split(".").map(Number);
  if (release.some((n) => !Number.isSafeInteger(n))) return null;
  while (release.length > 1 && release[release.length - 1] === 0) release.pop();
  const pre: [number, number] | null = m[3] ? [PRE_RANK[m[3].toLowerCase()]!, Number(m[4] ?? 0)] : null;
  const post = m[5] !== undefined ? Number(m[5]) : m[6] ? Number(m[7] ?? 0) : null;
  const dev = m[8] ? Number(m[9] ?? 0) : null;
  const local = m[10] ? m[10].toLowerCase().split(/[-_.]/).map((p) => (/^\d+$/.test(p) ? Number(p) : p)) : null;
  return { epoch: Number(m[1] ?? 0), release, pre, post, dev, local };
}

/** Comparable tuple following packaging's _cmpkey. */
function key(v: Pep440): { pre: [number, number]; post: number; dev: number } {
  let pre: [number, number];
  // 1.0.dev0 sorts before 1.0a0; a final release sorts after every pre-release of it.
  if (v.pre === null && v.post === null && v.dev !== null) pre = [-Infinity, 0];
  else if (v.pre === null) pre = [Infinity, 0];
  else pre = v.pre;
  return { pre, post: v.post ?? -Infinity, dev: v.dev ?? Infinity };
}

function compareLocal(a: (number | string)[] | null, b: (number | string)[] | null): number {
  if (a === null || b === null) return a === b ? 0 : a === null ? -1 : 1;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const p = a[i];
    const q = b[i];
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    // Numeric segments rank above alphanumeric ones.
    if (typeof p === "number" && typeof q === "number") {
      if (p !== q) return cmp(p, q);
    } else if (typeof p === "number") return 1;
    else if (typeof q === "number") return -1;
    else if (p !== q) return cmp(p, q);
  }
  return 0;
}

/** PEP 440 ordering. Null when either side is not a valid PEP 440 version. */
export function comparePep440(a: string, b: string): number | null {
  const x = parsePep440(a);
  const y = parsePep440(b);
  if (!x || !y) return null;
  if (x.epoch !== y.epoch) return cmp(x.epoch, y.epoch);
  for (let i = 0; i < Math.max(x.release.length, y.release.length); i++) {
    const d = cmp(x.release[i] ?? 0, y.release[i] ?? 0);
    if (d) return d;
  }
  const kx = key(x);
  const ky = key(y);
  return cmp(kx.pre[0], ky.pre[0]) || cmp(kx.pre[1], ky.pre[1]) || cmp(kx.post, ky.post) || cmp(kx.dev, ky.dev) || compareLocal(x.local, y.local);
}

// ---------------------------------------------------------------- ecosystem helpers

export function compareVersions(ecosystem: VersionEcosystem, a: string, b: string): number | null {
  return ecosystem === "npm" ? compareSemver(a, b) : comparePep440(a, b);
}

export function isValidVersion(ecosystem: VersionEcosystem, version: string): boolean {
  return ecosystem === "npm" ? parseSemver(version) !== null : parsePep440(version) !== null;
}

/** The lowest of `candidates` that is strictly above `current`; null when none is (or `current` is unparseable). */
export function lowestAbove(ecosystem: VersionEcosystem, current: string, candidates: readonly string[]): string | null {
  let best: string | null = null;
  for (const c of candidates) {
    const above = compareVersions(ecosystem, c, current);
    if (above === null || above <= 0) continue;
    if (best === null || (compareVersions(ecosystem, c, best) ?? 0) < 0) best = c;
  }
  return best;
}

/** The highest of the given versions (unparseable ones ignored). */
export function highest(ecosystem: VersionEcosystem, versions: readonly string[]): string | null {
  let best: string | null = null;
  for (const v of versions) {
    if (!isValidVersion(ecosystem, v)) continue;
    if (best === null || (compareVersions(ecosystem, v, best) ?? 0) > 0) best = v;
  }
  return best;
}
