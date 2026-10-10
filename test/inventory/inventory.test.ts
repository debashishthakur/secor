// Inventory acceptance tests (M1): one fixture project per framework; exact entry points, paths, methods and auth.
// Generated from a reviewed run, then frozen. Format: kind|service|method|path-or-name|file:line|g=guarded|via|guard

import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { entryPointId } from "../../src/engine/inventory.js";
import { runFixture } from "../helpers/fixtures.js";

const EXPECTED: Record<string, { units: unknown; entries: string[] }> = {
  "express": {
    "units": [
      {
        "kind": "api",
        "framework": "express",
        "root": ""
      }
    ],
    "entries": [
      "http_route|api|GET|/health|src/app.ts:10|g=false|null|",
      "http_route|api|POST|/login|src/app.ts:11|g=false|null|",
      "http_route|api|GET|/jwt|src/app.ts:14|g=true|middleware|passport.authenticate",
      "http_route|api|*|/mcp|src/app.ts:15|g=true|middleware|requireBearerAuth",
      "http_route|api|GET|/a|src/app.ts:16|g=false|null|",
      "http_route|api|GET|/b|src/app.ts:16|g=false|null|",
      "http_route|api|DELETE|/items/:id|src/app.ts:17|g=false|null|",
      "http_route|api|GET|/items/:id|src/app.ts:17|g=false|null|",
      "http_route|api|GET|/after-guard|src/app.ts:20|g=true|router|requireAuth",
      "http_route|api|DELETE|/admin/users/:userId|src/routes/admin.ts:5|g=true|router|ensureAdminSession",
      "http_route|api|GET|/api/users|src/routes/users.ts:3|g=false|null|",
      "http_route|api|GET|/api/users/:id|src/routes/users.ts:4|g=false|null|",
      "http_route|api|PUT|/api/users/:id|src/routes/users.ts:5|g=true|middleware|isAuthenticated"
    ]
  },
  "nextjs": {
    "units": [
      {
        "kind": "api",
        "framework": "nextjs",
        "root": ""
      },
      {
        "kind": "web",
        "framework": "nextjs",
        "root": ""
      }
    ],
    "entries": [
      "page|web||/dashboard/:slug*?|src/app/(admin)/dashboard/[[...slug]]/page.tsx:1|g=true|middleware|auth",
      "page|web||/login|src/app/@modal/login/page.tsx:1|g=false|null|",
      "server_action|api||src/app/actions.ts#subscribe|src/app/actions.ts:3|g=false|null|",
      "server_action|api||src/app/actions.ts#deletePost|src/app/actions.ts:4|g=true|handler|auth",
      "http_route|api|GET|/api/files/:path*|src/app/api/files/[...path]/route.ts:2|g=true|middleware|auth",
      "http_route|api|POST|/api/files/:path*|src/app/api/files/[...path]/route.ts:2|g=true|middleware|auth",
      "http_route|api|PATCH|/api/session|src/app/api/session/route.ts:2|g=true|handler|withAuth",
      "http_route|api|GET|/api/users/:id|src/app/api/users/[id]/route.ts:2|g=true|handler|auth",
      "http_route|api|DELETE|/api/users/:id|src/app/api/users/[id]/route.ts:7|g=false|null|",
      "server_action|api||src/app/inline.tsx#save|src/app/inline.tsx:2|g=false|null|",
      "page|web||/|src/app/page.tsx:1|g=false|null|",
      "page|web||/about|src/pages/about.tsx:1|g=false|null|",
      "http_route|api|*|/api/hello|src/pages/api/hello.ts:1|g=false|null|",
      "http_route|api|POST|/api/only-post|src/pages/api/only-post.ts:1|g=false|null|",
      "http_route|api|GET|/api/posts|src/pages/api/posts/index.ts:1|g=false|null|",
      "http_route|api|POST|/api/posts|src/pages/api/posts/index.ts:1|g=false|null|"
    ]
  },
  "fastapi": {
    "units": [
      {
        "kind": "api",
        "framework": "fastapi",
        "root": ""
      }
    ],
    "entries": [
      "http_route|api|GET|/health|app/main.py:8|g=false|null|",
      "http_route|api|GET|/me|app/main.py:12|g=true|dependency|get_current_user",
      "http_route|api|DELETE|/admin/users/:user_id|app/routers/admin.py:6|g=true|router|get_current_user",
      "http_route|api|GET|/api/items|app/routers/items.py:6|g=false|null|",
      "http_route|api|GET|/api/items/:item_id|app/routers/items.py:10|g=true|dependency|get_current_user",
      "http_route|api|GET|/api/items/:item_id/tags|app/routers/items.py:14|g=true|dependency|oauth2_scheme (OAuth2PasswordBearer)",
      "http_route|api|PUT|/api/items/:item_id/tags|app/routers/items.py:14|g=true|dependency|oauth2_scheme (OAuth2PasswordBearer)"
    ]
  },
  "vite": {
    "units": [
      {
        "kind": "web",
        "framework": "vite",
        "root": ""
      }
    ],
    "entries": []
  },
  "mcp-ts": {
    "units": [
      {
        "kind": "mcp",
        "framework": "mcp-ts",
        "root": ""
      }
    ],
    "entries": [
      "mcp_tool|mcp||add|src/lowlevel.ts:4|g=false|null|",
      "mcp_tool|mcp||run_query|src/lowlevel.ts:4|g=false|null|",
      "mcp_tool|mcp||read_file|src/server.ts:6|g=false|null|",
      "mcp_tool|mcp||echo|src/server.ts:7|g=false|null|",
      "mcp_resource|mcp||config|src/server.ts:8|g=false|null|",
      "mcp_prompt|mcp||summarise|src/server.ts:9|g=false|null|"
    ]
  },
  "mcp-py": {
    "units": [
      {
        "kind": "mcp",
        "framework": "mcp-py",
        "root": ""
      }
    ],
    "entries": [
      "mcp_tool|mcp||add|low.py:5|g=false|null|",
      "mcp_tool|mcp||delete_note|low.py:5|g=false|null|",
      "mcp_tool|mcp||read_file|server.py:5|g=false|null|",
      "mcp_tool|mcp||search_notes|server.py:9|g=false|null|",
      "mcp_resource|mcp||note|server.py:13|g=false|null|",
      "mcp_prompt|mcp||review|server.py:17|g=false|null|"
    ]
  }
};

const line = (e: { kind: string; service: string; method?: string; path?: string; name?: string; file: string; line: number; auth: { guarded: boolean; via: string | null; guard?: string } }) =>
  `${e.kind}|${e.service}|${e.method ?? ""}|${e.path ?? e.name}|${e.file}:${e.line}|g=${e.auth.guarded}|${e.auth.via}|${e.auth.guard ?? ""}`;

describe("inventory per framework", () => {
  for (const [fw, want] of Object.entries(EXPECTED)) {
    it(fw, async () => {
      const { result } = await runFixture(join(import.meta.dirname, "fixtures", fw), { onlyRules: [] });
      expect(result.units).toEqual(want.units);
      expect(result.inventory.map(line)).toEqual(want.entries);
      for (const e of result.inventory) expect(e.id).toBe(entryPointId(e));
      expect(new Set(result.inventory.map((e) => e.id)).size).toBe(result.inventory.length);
    });
  }
});

describe("guard resolution across files", () => {
  it("express: object-property middleware, aliased express-jwt, optional auth, namespace and object imports", async () => {
    const { result } = await runFixture(join(import.meta.dirname, "fixtures", "express-guards"), { onlyRules: [] });
    const by = Object.fromEntries(result.inventory.map((e) => [`${e.method} ${e.path}`, e.auth]));
    expect(by["GET /me"]).toEqual({ guarded: true, via: "middleware", guard: "expressjwt" });
    expect(by["GET /feed"]).toEqual({ guarded: false, via: null });
    expect(by["DELETE /admin/x"]).toEqual({ guarded: true, via: "middleware", guard: "requireAdmin" });
    expect(by["POST /admin/y"]).toEqual({ guarded: true, via: "middleware", guard: "requireAdmin" });
  });

  it("next.js: a guard inside an imported helper (one level) guards the handler; an unrelated helper does not", async () => {
    const { result } = await runFixture(join(import.meta.dirname, "fixtures", "nextjs-guards"), { onlyRules: [] });
    const by = Object.fromEntries(result.inventory.map((e) => [`${e.method} ${e.path}`, e.auth]));
    expect(by["GET /api/profile"]).toEqual({ guarded: true, via: "handler", guard: "getServerProfile → auth.getUser" });
    expect(by["GET /api/keys"]).toEqual({ guarded: false, via: null });
  });
});

describe("adapter forms found on real projects", () => {
  it("next.js: destructured route exports and pages-router fall-through methods", async () => {
    const { result } = await runFixture(join(import.meta.dirname, "fixtures", "nextjs-forms"), { onlyRules: [] });
    const routes = result.inventory.filter((e) => e.kind === "http_route").map((e) => `${e.method} ${e.path}`);
    expect(routes).toEqual(["GET /api/auth/:nextauth*", "POST /api/auth/:nextauth*", "* /api/fall", "POST /api/fall", "PUT /api/strict"]);
  });

  it("mcp-ts: tools without an input schema have no input names", async () => {
    const { prepareFixture } = await import("../helpers/fixtures.js");
    const root = prepareFixture(join(import.meta.dirname, "fixtures", "mcp-ts-forms"));
    const { mcpTsAdapter } = await import("../../src/engine/adapters/mcp.js");
    const { buildTestContext } = await import("../helpers/context.js");
    const ctx = await buildTestContext(root);
    const byName = Object.fromEntries(mcpTsAdapter({ ctx, unit: ctx.units[0]!, guards: undefined as never }).map((e) => [e.name, e.inputNames]));
    expect(byName).toEqual({ ping: [], ping2: [], annotated: [], read: ["path"], status: [], fetch: ["url"] });
  });
});

