import { describe, expect, it } from "vitest";
import { analyseExec, analyseShell, dockerInstructions } from "../../src/engine/rules/web/production-debug.js";
import { expandEnv, parseEnv } from "../../src/engine/rules/web/util.js";

describe("dev server detection in start commands", () => {
  const cases: [string, string | null, string | null][] = [
    ["next dev", "next dev", "next start"],
    ["next dev --turbopack -p 3000", "next dev", "next start -p 3000"],
    ["NODE_ENV=production next dev", "next dev", "NODE_ENV=production next start"],
    ["next start", null, null],
    ["next build && next start", null, null],
    ["vite", "vite", "vite preview"],
    ["vite --host 0.0.0.0 --port 80", "vite", "vite preview --host 0.0.0.0 --port 80"],
    ["vite dev", "vite", "vite preview"],
    ["vite serve --port 3000", "vite", "vite preview --port 3000"],
    ["vite preview", null, null],
    ["vite build && vite preview", null, null],
    ["vite build && vite", "vite", "vite build && vite preview"],
    ["npx vite", "vite", "npx vite preview"],
    ["nodemon src/index.js", "nodemon", "node src/index.js"],
    ["cross-env NODE_ENV=production nodemon server.js", "nodemon", "cross-env NODE_ENV=production node server.js"],
    ["nodemon --exec ts-node src/index.ts", "nodemon", null],
    ["uvicorn main:app --reload", "uvicorn --reload", "uvicorn main:app"],
    ["uvicorn main:app --host 0.0.0.0 --reload --port 8000", "uvicorn --reload", "uvicorn main:app --host 0.0.0.0 --port 8000"],
    ["python -m uvicorn app.main:app --reload", "uvicorn --reload", "python -m uvicorn app.main:app"],
    ["poetry run uvicorn main:app --reload --reload-dir src", "uvicorn --reload", null],
    ["uvicorn main:app --host 0.0.0.0", null, null],
    ["yarn next dev", "next dev", "yarn next start"],
    ["node dist/server.js", null, null],
  ];
  for (const [cmd, kind, fixed] of cases) {
    it(cmd, () => {
      const hit = analyseShell(cmd);
      if (kind === null) expect(hit).toBeNull();
      else expect(hit).toEqual({ kind, fixed });
    });
  }

  it("reports npm-script indirection for the caller to resolve", () => {
    expect(analyseShell("npm run dev")).toEqual({ kind: "script", scripts: ["dev"], fixed: null });
    expect(analyseShell("npm start")).toEqual({ kind: "script", scripts: ["start"], fixed: null });
    expect(analyseShell("yarn dev")).toEqual({ kind: "script", scripts: ["dev"], fixed: null });
    expect(analyseShell("npm run build && pnpm run serve")).toEqual({ kind: "script", scripts: ["build", "serve"], fixed: null });
    // a dev server run directly wins over script indirection
    expect(analyseShell("npm run build && next dev")).toEqual({ kind: "next dev", fixed: "npm run build && next start" });
    expect(analyseShell("npm ci")).toBeNull();
    expect(analyseShell("npm test")).toBeNull();
  });

  it("handles exec-form arrays, including sh -c", () => {
    expect(analyseExec(["uvicorn", "main:app", "--reload"])).toEqual({ kind: "uvicorn --reload", fixed: '["uvicorn", "main:app"]' });
    expect(analyseExec(["npx", "next", "dev"])).toEqual({ kind: "next dev", fixed: '["npx", "next", "start"]' });
    expect(analyseExec(["vite"])).toEqual({ kind: "vite", fixed: '["vite", "preview"]' });
    expect(analyseExec(["sh", "-c", "npm run build && next dev"])).toEqual({ kind: "next dev", fixed: '["sh", "-c", "npm run build && next start"]' });
    expect(analyseExec(["node", "server.js"])).toBeNull();
    expect(analyseExec(["npm", "run", "dev"])).toEqual({ kind: "script", scripts: ["dev"], fixed: null });
  });
});

describe("dockerInstructions", () => {
  it("reads instructions with continuations and line numbers", () => {
    const text = "FROM node:20 AS build\n# comment\nRUN npm ci && \\\n    npm run build\n\nFROM node:20-alpine\ncmd [\"node\", \\\n  \"server.js\"]\n";
    const ins = dockerInstructions(text);
    expect(ins.map((i) => `${i.instr}@${i.line}-${i.endLine}`)).toEqual(["FROM@1-1", "RUN@3-4", "FROM@6-6", "CMD@7-8"]);
    expect(ins[3]!.args).toBe('["node", "server.js"]');
    expect(ins[1]!.args).toBe("npm ci && npm run build");
  });
});

describe(".env parsing", () => {
  const text = [
    "# comment",
    "PLAIN=value # trailing comment",
    "export EXPORTED=1",
    'QUOTED="a b # not a comment"',
    "SINGLE='$NOT_EXPANDED'",
    'MULTI="line1',
    'line2"',
    "EMPTY=",
    "REF=${PLAIN}-x",
    "REF2=$MISSING",
    "DEFAULTED=${MISSING:-fallback}",
  ].join("\n");
  const entries = parseEnv(text);
  const get = (k: string) => entries.find((e) => e.key === k)!;

  it("parses keys, values, quotes and lines", () => {
    expect(entries.map((e) => e.key)).toEqual(["PLAIN", "EXPORTED", "QUOTED", "SINGLE", "MULTI", "EMPTY", "REF", "REF2", "DEFAULTED"]);
    expect(get("PLAIN")).toMatchObject({ value: "value", line: 2, quote: null });
    expect(get("QUOTED").value).toBe("a b # not a comment");
    expect(get("MULTI")).toMatchObject({ value: "line1\nline2", line: 6 });
    expect(get("EMPTY").value).toBe("");
    expect(text.slice(get("PLAIN").start, get("PLAIN").end)).toBe("PLAIN=value # trailing comment");
  });

  it("expands $VAR and ${VAR} like dotenv-expand, but not in single quotes", () => {
    const lookup = (k: string) => entries.find((e) => e.key === k)?.value;
    expect(expandEnv(get("REF"), lookup)).toBe("value-x");
    expect(expandEnv(get("REF2"), lookup)).toBeNull();
    expect(expandEnv(get("DEFAULTED"), lookup)).toBeNull();
    expect(expandEnv(get("SINGLE"), lookup)).toBeNull();
    expect(expandEnv(get("PLAIN"), lookup)).toBeNull();
  });
});
