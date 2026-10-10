// Normal: a code-hosting style server (also the "other managed server" in the name-collision case).
import { schema, serve } from "./_lib.mjs";

await serve({
  name: "normal-github",
  tools: [
    { name: "search_code", description: "Search code in the user's repositories.", inputSchema: schema({ q: { type: "string", maxLength: 256 } }, ["q"]) },
    { name: "create_issue", description: "Open an issue in a repository.", inputSchema: schema({ repo: { type: "string", maxLength: 100 }, title: { type: "string", maxLength: 200 }, body: { type: "string", maxLength: 500 } }, ["repo", "title"]) },
    { name: "list_pull_requests", description: "List open pull requests in a repository.", inputSchema: schema({ repo: { type: "string", maxLength: 100 } }, ["repo"]) },
  ],
});
