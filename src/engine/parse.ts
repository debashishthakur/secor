// tree-sitter (WASM) parsing for JavaScript, TypeScript, TSX and Python. Grammars ship in grammars/.

import { join } from "node:path";
import { Language, type Node, Parser, type Tree } from "web-tree-sitter";
import { packageRoot } from "./util/paths.js";

export type SyntaxNode = Node;
export type Lang = "javascript" | "typescript" | "tsx" | "python";

const GRAMMAR_FILES: Record<Lang, string> = {
  javascript: "tree-sitter-javascript.wasm",
  typescript: "tree-sitter-typescript.wasm",
  tsx: "tree-sitter-tsx.wasm",
  python: "tree-sitter-python.wasm",
};

let ready: Promise<void> | null = null;
const parsers = new Map<Lang, Parser>();

/** Load the runtime and all four grammars once per process. */
export function initParsers(): Promise<void> {
  ready ??= (async () => {
    await Parser.init();
    for (const lang of Object.keys(GRAMMAR_FILES) as Lang[]) {
      const language = await Language.load(join(packageRoot(), "grammars", GRAMMAR_FILES[lang]));
      const parser = new Parser();
      parser.setLanguage(language);
      parsers.set(lang, parser);
    }
  })();
  return ready;
}

export function langForFile(file: string): Lang | null {
  if (/\.d\.[cm]?ts$/.test(file)) return null;
  if (/\.(?:js|mjs|cjs|jsx)$/.test(file)) return "javascript";
  if (/\.(?:ts|mts|cts)$/.test(file)) return "typescript";
  if (/\.tsx$/.test(file)) return "tsx";
  if (/\.py$/.test(file)) return "python";
  return null;
}

export function isJsLang(lang: Lang): boolean {
  return lang !== "python";
}

/** Parse source synchronously. initParsers() must have completed. */
export function parseSource(source: string, lang: Lang): Tree {
  const parser = parsers.get(lang);
  if (!parser) throw new Error("parsers not initialised: call initParsers() first");
  const tree = parser.parse(source);
  if (!tree) throw new Error(`tree-sitter failed to parse (${lang})`);
  return tree;
}

export interface ParsedFile {
  file: string;
  lang: Lang;
  source: string;
  tree: Tree;
  root: SyntaxNode;
  /** Memoised per-file analyses (imports, declarations, ...), keyed by helper name. */
  memo: Map<string, unknown>;
}

export function memo<T>(pf: ParsedFile, key: string, compute: () => T): T {
  if (pf.memo.has(key)) return pf.memo.get(key) as T;
  const v = compute();
  pf.memo.set(key, v);
  return v;
}
