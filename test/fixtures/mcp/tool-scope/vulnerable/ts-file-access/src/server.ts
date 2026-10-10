import fs from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const ROOT = process.env.NOTES_ROOT ?? "/srv/notes";

export const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool("read_note", { path: z.string() }, async ({ path: notePath }) => {
  const text = await readFile(path.join(ROOT, notePath), "utf8");
  return { content: [{ type: "text", text }] };
});

server.registerTool(
  "save_note",
  { description: "Save a note", inputSchema: { name: z.string(), body: z.string() } },
  async (args) => {
    fs.writeFileSync(path.join(ROOT, args.name), args.body);
    return { content: [{ type: "text", text: "saved" }] };
  },
);

server.tool("note_size", { name: z.string() }, async ({ name }) => {
  const size = fs.statSync(path.join(ROOT, name)).size;
  return { content: [{ type: "text", text: String(size) }] };
});

if (process.argv.includes("--stdio")) await server.connect(new StdioServerTransport());
