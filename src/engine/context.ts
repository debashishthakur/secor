// ProjectContext: files, parse cache, config, detection and inventory for one Ship run.

import { closeSync, lstatSync, openSync, readSync } from "node:fs";
import { isAbsolute, join, relative, resolve } from "node:path";
import type { Framework, NotCheckedEntry, Pack, ServiceKind } from "../types.js";
import type { ProjectConfig } from "./config.js";
import type { Detection, UnitInfo } from "./detect.js";
import { type GitInfo } from "./files.js";
import type { InventoryEntry } from "./inventory-types.js";
import type { NetClient } from "./net.js";
import { type ParsedFile, langForFile, parseSource } from "./parse.js";
import { toPosix } from "./util/paths.js";

export const MAX_READ_BYTES = 2 * 1024 * 1024;

export interface ContextInit {
  root: string;
  name: string;
  config: ProjectConfig;
  files: string[];
  git: GitInfo;
  packs: Set<Pack>;
  network: boolean;
  net: NetClient;
  runStartedAt: Date;
}

export class ProjectContext {
  readonly root: string;
  readonly name: string;
  readonly config: ProjectConfig;
  readonly files: string[];
  readonly fileSet: Set<string>;
  readonly git: GitInfo;
  readonly packs: Set<Pack>;
  readonly network: boolean;
  readonly net: NetClient;
  readonly runStartedAt: Date;
  detection!: Detection;
  units: UnitInfo[] = [];
  inventory: InventoryEntry[] = [];
  /** Partial gaps reported by rules ("Git history: git not available"); the rule still counts as ran. */
  readonly gaps: NotCheckedEntry[] = [];
  private readonly textCache = new Map<string, string | null>();
  private readonly parseCache = new Map<string, ParsedFile | null>();

  constructor(init: ContextInit) {
    this.root = init.root;
    this.name = init.name;
    this.config = init.config;
    this.files = init.files;
    this.fileSet = new Set(init.files);
    this.git = init.git;
    this.packs = init.packs;
    this.network = init.network;
    this.net = init.net;
    this.runStartedAt = init.runStartedAt;
  }

  hasFile(rel: string): boolean {
    return this.fileSet.has(rel);
  }

  /** Absolute path for a project-relative path, or null if it escapes the project root. */
  abs(rel: string): string | null {
    if (isAbsolute(rel)) return null;
    const p = resolve(this.root, rel);
    const back = relative(this.root, p);
    if (back.startsWith("..") || isAbsolute(back)) return null;
    return p;
  }

  /**
   * Text of a project file (listed or not), cached unless `cache: false`. Null when missing, outside the root,
   * a symlink, larger than 2 MB, or binary.
   */
  read(rel: string, opts: { cache?: boolean } = {}): string | null {
    if (this.textCache.has(rel)) return this.textCache.get(rel)!;
    let text: string | null = null;
    const p = this.abs(rel);
    if (p) {
      try {
        const st = lstatSync(p);
        if (st.isFile() && st.size <= MAX_READ_BYTES) {
          const fd = openSync(p, "r");
          try {
            const buf = Buffer.alloc(st.size);
            readSync(fd, buf, 0, st.size, 0);
            if (!buf.subarray(0, 8000).includes(0)) text = buf.toString("utf8");
          } finally {
            closeSync(fd);
          }
        }
      } catch {
        text = null;
      }
    }
    // `cache: false` for whole-repo scans (core/secrets) so every file's text is not held for the whole run.
    if (opts.cache !== false) this.textCache.set(rel, text);
    return text;
  }

  /** Parsed syntax tree for a JS/TS/TSX/Python file, cached. */
  parse(rel: string): ParsedFile | null {
    if (this.parseCache.has(rel)) return this.parseCache.get(rel)!;
    let pf: ParsedFile | null = null;
    const lang = langForFile(rel);
    const source = lang ? this.read(rel) : null;
    if (lang && source !== null) {
      try {
        const tree = parseSource(source, lang);
        pf = { file: rel, lang, source, tree, root: tree.rootNode, memo: new Map() };
      } catch {
        pf = null;
      }
    }
    this.parseCache.set(rel, pf);
    return pf;
  }

  /** Listed source files that tree-sitter can parse, optionally limited to a unit. */
  codeFiles(unit?: UnitInfo, lang?: "js" | "py"): string[] {
    const list = unit ? unit.files : this.files;
    return list.filter((f) => {
      const l = langForFile(f);
      if (!l) return false;
      if (lang === "py") return l === "python";
      if (lang === "js") return l !== "python";
      return true;
    });
  }

  unitsOf(kind?: ServiceKind, framework?: Framework): UnitInfo[] {
    return this.units.filter((u) => (!kind || u.kind === kind) && (!framework || u.framework === framework));
  }

  hasUnit(kind: ServiceKind): boolean {
    return this.units.some((u) => u.kind === kind);
  }

  addGap(area: string, reason: string): void {
    if (!this.gaps.some((g) => g.area === area && g.reason === reason)) this.gaps.push({ area, reason });
  }

  rel(abs: string): string {
    return toPosix(relative(this.root, abs));
  }

  joinRoot(...parts: string[]): string {
    return join(this.root, ...parts);
  }

  dispose(): void {
    for (const pf of this.parseCache.values()) pf?.tree.delete();
    this.parseCache.clear();
    this.textCache.clear();
  }
}
