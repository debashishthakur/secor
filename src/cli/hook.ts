// `secor hook pre|post|protect` (spec section 9.4). Internal: called by Claude Code. Always exits 0.
// This is the fast path taken by src/cli/index.ts before commander loads. It imports only src/connect/hooks.ts,
// lazily, which never loads tree-sitter, commander or the MCP SDK.

export interface HookCommandIO {
  /** Hook input; defaults to process.stdin. */
  stdin?: string | AsyncIterable<Buffer | string>;
  stdout?: { write(text: string): unknown };
  /** Work budget in ms (default 3000), for tests. */
  budgetMs?: number;
  now?: () => Date;
}

const MAX_STDIN_BYTES = 64 * 1024 * 1024;
const BUDGET_MS = 3000;

/** Read the whole stream, giving up (returning "") at the deadline or past the size cap. */
async function readAll(stream: AsyncIterable<Buffer | string>, deadline: number): Promise<string> {
  const reading = (async () => {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const c of stream) {
      const b = typeof c === "string" ? Buffer.from(c, "utf8") : c;
      size += b.length;
      if (size > MAX_STDIN_BYTES) return "";
      chunks.push(b);
    }
    return Buffer.concat(chunks).toString("utf8");
  })().catch(() => "");
  let timer: NodeJS.Timeout | undefined;
  const late = new Promise<string>((resolve) => {
    timer = setTimeout(() => resolve(""), Math.max(0, deadline - Date.now()));
    timer.unref();
  });
  try {
    return await Promise.race([reading, late]);
  } finally {
    clearTimeout(timer);
  }
}

export async function runHookCommand(phase: string, io: HookCommandIO = {}): Promise<number> {
  const startedAt = Date.now();
  if (phase !== "pre" && phase !== "post" && phase !== "protect") return 0;
  const out = io.stdout ?? process.stdout;
  const budgetMs = io.budgetMs ?? BUDGET_MS;
  try {
    const text = typeof io.stdin === "string" ? io.stdin : await readAll(io.stdin ?? process.stdin, startedAt + budgetMs);
    if (io.stdin === undefined) process.stdin.destroy();
    const { runHook } = await import("../connect/hooks.js");
    const result = await runHook(phase, text, { startedAt, budgetMs, ...(io.now ? { now: io.now } : {}) });
    if (result) out.write(`${result}\n`);
  } catch {
    // Fail open: nothing on stdout, exit 0 (invariant 10).
  }
  return 0;
}
