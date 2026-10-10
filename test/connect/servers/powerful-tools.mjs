// Bad (low): tools that run commands and delete files.
import { schema, serve } from "./_lib.mjs";

await serve({
  name: "powerful-tools",
  tools: [
    { name: "run_command", description: "Run a command on the host.", inputSchema: schema({ cmd: { type: "string", maxLength: 500 } }, ["cmd"]) },
    { name: "delete_file", description: "Delete a file by path.", inputSchema: schema({ path: { type: "string", maxLength: 500 } }, ["path"]) },
    { name: "list_files", description: "List files in a folder.", inputSchema: schema({ dir: { type: "string", maxLength: 500 } }, ["dir"]) },
  ],
});
