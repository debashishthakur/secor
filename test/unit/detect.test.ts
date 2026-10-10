// Service-unit and framework detection (spec 8.2).

import { describe, expect, it } from "vitest";
import { constructsMcpServerPy, constructsMcpServerTs, detectUnits } from "../../src/engine/detect.js";

function detect(files: Record<string, string>, mcpDeployment: "auto" | "local" | "remote" = "auto") {
  const list = Object.keys(files).sort();
  return detectUnits({ files: list, read: (f) => files[f] ?? null, mcpDeployment });
}
const pkg = (deps: Record<string, string>, dev: Record<string, string> = {}) => JSON.stringify({ dependencies: deps, devDependencies: dev });
const units = (d: ReturnType<typeof detect>) => d.units.map((u) => `${u.kind}/${u.framework}@${u.root || "."}`);

describe("framework detection", () => {
  it("monorepo: each package.json / pyproject.toml / requirements.txt directory is a candidate root", () => {
    const d = detect({
      "package.json": JSON.stringify({ name: "mono", workspaces: ["apps/*"] }),
      "apps/web/package.json": pkg({ next: "16.0.0" }),
      "apps/web/app/page.tsx": "export default function P() {}",
      "apps/api/package.json": pkg({ express: "5.0.0" }),
      "apps/api/src/index.ts": "",
      "services/py/requirements.txt": "fastapi==0.115.0\n",
      "services/py/main.py": "",
      "tools/mcp/package.json": pkg({ "@modelcontextprotocol/sdk": "1.30.1" }),
      "tools/mcp/src/server.ts": 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\nconst s = new McpServer({ name: "x", version: "1" });',
    });
    expect(units(d)).toEqual(["api/express@apps/api", "api/nextjs@apps/web", "web/nextjs@apps/web", "api/fastapi@services/py", "mcp/mcp-ts@tools/mcp"]);
    expect(d.units.find((u) => u.root === "apps/api")!.files).toEqual(["apps/api/package.json", "apps/api/src/index.ts"]);
  });

  it("Next.js needs an app/, src/app/, pages/ or src/pages/ directory", () => {
    expect(units(detect({ "package.json": pkg({ next: "16" }), "lib/x.ts": "" }))).toEqual([]);
    expect(units(detect({ "package.json": pkg({ next: "16" }), "src/pages/index.tsx": "" }))).toEqual(["api/nextjs@.", "web/nextjs@."]);
  });

  it("Vite needs index.html at the unit root; vite in devDependencies counts", () => {
    expect(units(detect({ "package.json": pkg({}, { vite: "7" }) }))).toEqual([]);
    expect(units(detect({ "package.json": pkg({}, { vite: "7" }), "index.html": "<html></html>" }))).toEqual(["web/vite@."]);
  });

  it("FastAPI from requirements*.txt or pyproject.toml (PEP 621 and Poetry)", () => {
    expect(units(detect({ "requirements-prod.txt": "FastAPI[all]>=0.110 ; python_version>'3.8'\n" }))).toEqual(["api/fastapi@."]);
    expect(units(detect({ "pyproject.toml": '[project]\nname="x"\ndependencies=["fastapi>=0.110"]\n' }))).toEqual(["api/fastapi@."]);
    expect(units(detect({ "pyproject.toml": '[tool.poetry.dependencies]\npython="^3.12"\nfastapi={version="^0.110", extras=["all"]}\n' }))).toEqual(["api/fastapi@."]);
  });

  it("MCP (TS) needs the SDK dependency and a file constructing McpServer or the SDK Server", () => {
    expect(units(detect({ "package.json": pkg({ "@modelcontextprotocol/sdk": "1" }), "src/client.ts": 'import { Client } from "@modelcontextprotocol/sdk/client/index.js";' }))).toEqual([]);
    expect(units(detect({ "package.json": pkg({ "@modelcontextprotocol/sdk": "1", "socket.io": "4" }), "src/io.ts": 'import { Server } from "socket.io";\nnew Server(3000);' }))).toEqual([]);
    expect(units(detect({ "package.json": pkg({ "@modelcontextprotocol/sdk": "1" }), "src/s.ts": 'import { Server } from "@modelcontextprotocol/sdk/server/index.js";\nconst s = new Server({}, {});' }))).toEqual(["mcp/mcp-ts@."]);
  });

  it("MCP (Py): FastMCP, MCPServer (mcp 2.x) or a low-level Server imported from mcp.server", () => {
    expect(constructsMcpServerPy('from mcp.server.fastmcp import FastMCP\nmcp = FastMCP("x")')).toBe(true);
    expect(constructsMcpServerPy('from mcp.server.mcpserver import MCPServer\nmcp = MCPServer("x")')).toBe(true);
    expect(constructsMcpServerPy('from mcp.server.lowlevel import Server\nserver = Server("x")')).toBe(true);
    expect(constructsMcpServerPy("from http.server import Server\ns = Server()")).toBe(false);
    expect(constructsMcpServerTs("const s = new McpServer({})")).toBe(true);
    expect(units(detect({ "pyproject.toml": '[project]\ndependencies=["fastmcp>=2"]\n', "server.py": "from fastmcp import FastMCP\nmcp = FastMCP('x')\n" }))).toEqual(["mcp/mcp-py@."]);
  });

  it("Supabase and Firebase backends", () => {
    expect([...detect({ "package.json": pkg({ "@supabase/ssr": "0.5" }) }).backends]).toEqual(["supabase"]);
    expect([...detect({ "requirements.txt": "supabase==2.0.0\n" }).backends]).toEqual(["supabase"]);
    expect([...detect({ "package.json": pkg({ "firebase-admin": "12" }) }).backends]).toEqual(["firebase"]);
    expect([...detect({ "package.json": pkg({}), "firebase.json": "{}" }).backends]).toEqual(["firebase"]);
  });
});

describe("unsupported frameworks are listed in notChecked", () => {
  it("Django, Flask, Hono, Rails, Go", () => {
    const d = detect({
      "manage.py": "",
      "requirements.txt": "flask==3.0.0\n",
      "web/package.json": pkg({ hono: "4" }),
      "rb/Gemfile": "gem 'rails', '~> 7.1'\n",
      "svc/go.mod": "module x\n",
      "other/Gemfile": "gem 'sinatra'\n",
    });
    expect(d.notChecked).toEqual([
      { area: "Django routes", reason: "not supported in v1" },
      { area: "Flask routes", reason: "not supported in v1" },
      { area: "Go routes", reason: "not supported in v1" },
      { area: "Hono routes", reason: "not supported in v1" },
      { area: "Rails routes", reason: "not supported in v1" },
    ]);
  });
});

describe("MCP transport and deployment", () => {
  const ts = (code: string, extra: Record<string, string> = {}) =>
    detect({ "package.json": pkg({ "@modelcontextprotocol/sdk": "1" }), "src/s.ts": `const s = new McpServer({});\n${code}`, ...extra }).units[0]!.mcp!;

  it("TS: StdioServerTransport → stdio; StreamableHTTP / SSE → http; none → stdio", () => {
    expect([...ts("new StdioServerTransport()").transports]).toEqual(["stdio"]);
    expect([...ts("new StreamableHTTPServerTransport({})").transports]).toEqual(["http"]);
    expect([...ts("new SSEServerTransport('/m', res)").transports]).toEqual(["http"]);
    expect([...ts("new StdioServerTransport(); new StreamableHTTPServerTransport({})").transports].sort()).toEqual(["http", "stdio"]);
    expect([...ts("").transports]).toEqual(["stdio"]);
  });

  it("Py: run() / run(transport=...) / *_app()", () => {
    const py = (code: string) => detect({ "requirements.txt": "mcp==1.30.0\n", "s.py": `mcp = FastMCP("x")\n${code}` }).units[0]!.mcp!;
    expect([...py("mcp.run()").transports]).toEqual(["stdio"]);
    expect([...py('mcp.run(transport="stdio")').transports]).toEqual(["stdio"]);
    expect([...py('mcp.run(transport="streamable-http")').transports]).toEqual(["http"]);
    expect([...py("mcp.run('sse')").transports]).toEqual(["http"]);
    expect([...py("app = mcp.streamable_http_app()").transports]).toEqual(["http"]);
  });

  it("deployment: remote when a deploy file exists at the unit root or project root; config overrides", () => {
    expect(ts("", { Dockerfile: "FROM node" }).deployment).toBe("remote");
    expect(ts("", { "fly.toml": "" }).deployment).toBe("remote");
    expect(ts("").deployment).toBe("local");
    const d = detect({ "srv/package.json": pkg({ "@modelcontextprotocol/sdk": "1" }), "srv/s.ts": "new McpServer({})", "srv/Procfile": "web: node s.js" });
    expect(d.units[0]!.mcp!.deployment).toBe("remote");
    expect(detect({ "package.json": pkg({ "@modelcontextprotocol/sdk": "1" }), "s.ts": "new McpServer({})", Dockerfile: "" }, "local").units[0]!.mcp!.deployment).toBe("local");
  });
});

describe("transport and deployment forms found on real projects", () => {
  it("Python low-level servers served over HTTP are http; uvicorn/asyncio/subprocess .run() are not MCP runs", () => {
    const low = detect({ "requirements.txt": "mcp==1.30.0\n", "server.py": "from mcp.server.lowlevel import Server\nserver = Server('x')\nmanager = StreamableHTTPSessionManager(app=server)\nuvicorn.run(app, host='0.0.0.0')\n" });
    expect([...low.units[0]!.mcp!.transports]).toEqual(["http"]);
    const fast = detect({ "requirements.txt": "mcp==1.30.0\n", "s.py": "mcp = FastMCP('x')\nsubprocess.run(['ls'])\nasyncio.run(main())\nmcp.run(transport='streamable-http')\n" });
    expect([...fast.units[0]!.mcp!.transports]).toEqual(["http"]);
  });

  it("Cloudflare McpAgent and Vercel mcp-handler servers are http and remote", () => {
    const cf = detect({ "package.json": pkg({ "@modelcontextprotocol/sdk": "1", agents: "0.2" }), "src/index.ts": 'import { McpAgent } from "agents/mcp";\nexport class MyMCP extends McpAgent { server = new McpServer({ name: "x", version: "1" }); }' });
    expect(cf.units[0]!.mcp).toMatchObject({ deployment: "remote" });
    expect([...cf.units[0]!.mcp!.transports]).toEqual(["http"]);
    const vercel = detect({ "package.json": pkg({ "@modelcontextprotocol/sdk": "1", "mcp-handler": "1" }), "app/api/[transport]/route.ts": 'import { createMcpHandler } from "mcp-handler";\nconst handler = createMcpHandler((server) => {});\nconst s = new McpServer({});' });
    expect(vercel.units.find((u) => u.kind === "mcp")!.mcp).toMatchObject({ deployment: "remote" });
  });

  it("wrangler.jsonc counts as a deployment file", () => {
    const d = detect({ "package.json": pkg({ "@modelcontextprotocol/sdk": "1" }), "s.ts": "new McpServer({})", "wrangler.jsonc": "{}" });
    expect(d.units[0]!.mcp!.deployment).toBe("remote");
  });
});

