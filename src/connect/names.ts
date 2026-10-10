// MCP naming as Claude Code exposes it to hooks (spec section 9.4): tools are "mcp__<server>__<tool>", plugin servers
// "mcp__plugin_<plugin>_<server>__<tool>", and characters outside [A-Za-z0-9_-] in names become "_".
// Kept dependency-free: the hook process imports it.

/** SECOR's own MCP server, as a configured server ("secor") or the plugin-bundled one. */
export const SECOR_SERVER_NAMES: ReadonlySet<string> = new Set(["secor", "plugin_secor_secor"]);

export function normalizeMcpName(name: string): string {
  return name.replace(/[^A-Za-z0-9_-]/g, "_");
}

/** Split a hook tool_name into server and tool parts (spec 9.4 pre step 1), or null for non-MCP tools. */
export function parseMcpToolName(toolName: unknown): { server: string; tool: string } | null {
  if (typeof toolName !== "string") return null;
  const m = /^mcp__(.+?)__(.+)$/s.exec(toolName);
  return m ? { server: m[1]!, tool: m[2]! } : null;
}

/** True for printable ASCII names that can be written into scopes.yaml as they are. */
export function isPlainName(name: string): boolean {
  return /^[\x21-\x7E]{1,200}$/.test(name);
}
