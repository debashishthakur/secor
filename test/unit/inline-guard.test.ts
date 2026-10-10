// Inline credential checks count as handler guards (DECISIONS.md); look-alikes without a credential or an exit do not.

import { beforeAll, describe, expect, it } from "vitest";
import { isFunction } from "../../src/engine/ast.js";
import { inlineCredentialCheck } from "../../src/engine/inventory.js";
import { type ParsedFile, initParsers, parseSource } from "../../src/engine/parse.js";

beforeAll(() => initParsers());

function check(code: string, lang: "typescript" | "python" = "typescript"): boolean {
  const tree = parseSource(code, lang);
  const pf: ParsedFile = { file: "x", lang, source: code, tree, root: tree.rootNode, memo: new Map() };
  const fn = tree.rootNode.descendantsOfType(lang === "python" ? ["function_definition"] : ["arrow_function", "function_declaration"]).find((n) => isFunction(n ?? null))!;
  return inlineCredentialCheck(fn, pf);
}

describe("inline credential checks", () => {
  it("recognise the common idioms", () => {
    expect(check("app.get('/x', (req, res) => { if (!req.user) return res.sendStatus(401); res.json(req.user); })")).toBe(true);
    expect(check("const h = async (req, res, next) => { const u = users.get(req.cookies.token); if (!u) { next(new Error('blocked')); return } res.json(u) }")).toBe(true);
    expect(check("async function GET() { const s = cookies().get('session'); if (!s) redirect('/login'); return Response.json({}) }")).toBe(true);
    expect(check("const h = (req, res, next) => { const u = users.get(req.headers?.authorization?.replace('Bearer ', '')); if (u) { res.json(u) } else { next(new Error('blocked')) } }")).toBe(true);
    expect(check("const h = (req, res) => { const auth = req.headers.authorization; if (auth === undefined) return res.status(403).end(); res.end() }")).toBe(true);
    expect(check("def handler(request):\n    user = request.session.get('user')\n    if not user:\n        raise HTTPException(status_code=401)\n    return user\n", "python")).toBe(true);
  });

  it("ignore look-alikes", () => {
    expect(check("const h = (req, res) => { const user = req.user; res.json(user) }")).toBe(false);
    expect(check("const h = (req, res) => { if (!req.body.name) return res.status(400).end(); res.end() }")).toBe(false);
    expect(check("const h = (req, res) => { if (req.user) console.log('hi'); res.json([]) }")).toBe(false);
    expect(check("const h = (req, res) => { if (req.user) { audit(req.user) } else { log('anon') } res.json([]) }")).toBe(false);
    expect(check("const h = (req, res) => { const token = req.cookies.token; log(token); res.json({}) }")).toBe(false);
    expect(check("def handler(request):\n    if not request.query_params.get('q'):\n        raise HTTPException(400)\n    return []\n", "python")).toBe(false);
  });
});
