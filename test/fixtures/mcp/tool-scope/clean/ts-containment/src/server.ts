import fs from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { resolveInside } from "./paths.js";

const ROOT = path.resolve(process.env.NOTES_ROOT ?? "./notes");

const server = new McpServer({ name: "notes", version: "1.0.0" });

server.tool("read_note", { path: z.string() }, async ({ path: notePath }) => {
  const resolved = path.resolve(ROOT, notePath);
  if (!resolved.startsWith(ROOT + path.sep)) throw new Error("path outside the notes folder");
  const text = await readFile(resolved, "utf8");
  return { content: [{ type: "text", text }] };
});

server.tool("save_note", { name: z.string(), body: z.string() }, async ({ name, body }) => {
  const target = resolveInside(ROOT, name);
  fs.writeFileSync(target, body);
  return { content: [{ type: "text", text: "saved" }] };
});

server.tool("read_attachment", { file: z.string() }, async ({ file }) => {
  const text = await readFile(path.join(ROOT, "attachments", path.basename(file)), "utf8");
  return { content: [{ type: "text", text }] };
});

server.tool("read_by_id", { id: z.number().int() }, async ({ id }) => {
  const text = await readFile(path.join(ROOT, `${id}.md`), "utf8");
  return { content: [{ type: "text", text }] };
});

await server.connect(new StdioServerTransport());
