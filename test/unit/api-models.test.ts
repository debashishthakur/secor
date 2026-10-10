// Model sources for the api pack (src/engine/models.ts) and pure helpers of the api rules.

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { defaultConfig } from "../../src/engine/config.js";
import { ProjectContext } from "../../src/engine/context.js";
import { type ModelInfo, modelIndex, parsePrismaSchema, parseRlsTables, parseSqlTables, pydanticFields, sensitiveFields } from "../../src/engine/models.js";
import { initParsers, parseSource } from "../../src/engine/parse.js";
import type { UnitInfo } from "../../src/engine/detect.js";
import { parsePackageJson } from "../../src/engine/deps.js";
import { expressApp, fastapiApp, importPathFrom, jsTestFlag, pyTypeName } from "../../src/engine/rules/api/common.js";
import { mockNet } from "../helpers/fixtures.js";

const temps: string[] = [];

beforeAll(async () => {
  await initParsers();
});

afterAll(() => {
  for (const t of temps) rmSync(t, { recursive: true, force: true });
});

function project(files: Record<string, string>): ProjectContext {
  const root = mkdtempSync(join(tmpdir(), "secor-api-models-"));
  temps.push(root);
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
  return new ProjectContext({
    root,
    name: "t",
    config: defaultConfig(),
    files: Object.keys(files).sort(),
    git: { available: false, isRepo: false, tracked: new Set() },
    packs: new Set(["core", "api"]),
    network: false,
    net: mockNet({}),
    runStartedAt: new Date(0),
  });
}

describe("Prisma schema", () => {
  it("reads model and view fields, skipping block attributes and comments", () => {
    const models = parsePrismaSchema(
      [
        "// comment",
        "model User {",
        "  id           String @id // trailing comment",
        "  passwordHash String",
        "  posts        Post[]",
        "  @@map(\"users\")",
        "}",
        "enum Role { ADMIN USER }",
        "view ActiveUser {",
        "  id    String @unique",
        "  email String",
        "}",
      ].join("\n"),
      "prisma/schema.prisma",
    );
    expect(models.map((m) => [m.name, m.fields, m.line])).toEqual([
      ["User", ["id", "passwordHash", "posts"], 2],
      ["ActiveUser", ["id", "email"], 9],
    ]);
  });
});

describe("Supabase migrations", () => {
  it("reads CREATE TABLE columns (schema prefix, quotes, nested parentheses, constraints) and ALTER TABLE ADD COLUMN", () => {
    const sql = [
      "create table if not exists public.\"profiles\" (",
      "  id uuid primary key references auth.users (id) on delete cascade,",
      "  \"display_name\" text check (char_length(display_name) >= 3), -- a comment, with a comma",
      "  balance numeric(10, 2) default 0,",
      "  constraint profiles_pk unique (id, display_name)",
      ");",
      "alter table public.profiles add column api_key text, add column if not exists otp_secret text;",
      "CREATE TABLE notes (id bigint, body text);",
    ].join("\n");
    const tables = parseSqlTables(sql, "supabase/migrations/0001.sql");
    expect(tables.map((t) => [t.name, t.fields])).toEqual([
      ["profiles", ["id", "display_name", "balance", "api_key", "otp_secret"]],
      ["notes", ["id", "body"]],
    ]);
  });

  it("finds tables whose RLS policy references auth.uid()", () => {
    const sql = [
      'create policy "own rows" on public.notes for all using ((select auth.uid()) = user_id);',
      "create policy public_read on posts for select using (true);",
      'create policy "insert own" on "todos" for insert with check (auth.uid() = owner);',
    ].join("\n");
    expect(parseRlsTables(sql)).toEqual(["notes", "todos"]);
  });
});

describe("modelIndex", () => {
  const ctx = () =>
    project({
      "prisma/schema.prisma": "model Account {\n  id String @id\n  apiKey String\n}\n",
      "db/schema.ts": [
        'import { pgTable, serial, text } from "drizzle-orm/pg-core";',
        'export const users = pgTable("users", { id: serial("id"), passwordHash: text("password_hash") });',
        'export const posts = pgTable("posts", (t) => ({ id: t.integer(), title: t.text() }));',
      ].join("\n"),
      "models/member.js": [
        'const mongoose = require("mongoose");',
        "const memberSchema = new mongoose.Schema({",
        "  email: String,",
        "  password: { type: String, select: false },",
        "  auth: { resetToken: String },",
        "});",
        'module.exports = mongoose.models.Member || mongoose.model("Member", memberSchema);',
      ].join("\n"),
      "models/session.js": [
        'const { Schema, model } = require("mongoose");',
        "const s = new Schema({ token: String });",
        's.set("toJSON", { transform: (_doc, ret) => { delete ret.token; return ret; } });',
        'const Session = model("Session", s);',
        "module.exports = Session;",
      ].join("\n"),
      "supabase/migrations/0001_init.sql": "create table profiles (id uuid, api_key text);\ncreate policy p on profiles using (auth.uid() = id);\n",
      "app/models.py": [
        "from sqlalchemy import Column, Integer, String",
        "from sqlalchemy.orm import Mapped, deferred, mapped_column, relationship",
        "from sqlmodel import Field, SQLModel",
        "",
        "class User(Base):",
        '    __tablename__ = "users"',
        "    id = Column(Integer, primary_key=True)",
        "    hashed_password: Mapped[str] = mapped_column(String)",
        "    recovery_code = deferred(Column(String))",
        '    items = relationship("Item")',
        "",
        "class HeroBase(SQLModel):",
        "    name: str",
        "",
        "class Hero(HeroBase, table=True):",
        "    id: int | None = Field(default=None, primary_key=True)",
        "    secret_name: str",
      ].join("\n"),
      "app/schemas.py": [
        "from pydantic import BaseModel",
        "",
        "class UserBase(BaseModel):",
        "    email: str",
        "",
        "class UserCreate(UserBase):",
        "    password: str",
        "    is_admin: bool = False",
      ].join("\n"),
    });

  it("indexes every model source", () => {
    const idx = modelIndex(ctx());
    const fields = (m: ModelInfo | undefined) => m?.fields;
    expect(fields(idx.prisma.get("account"))).toEqual(["id", "apiKey"]);
    expect(fields(idx.drizzle.get("users"))).toEqual(["id", "passwordHash"]);
    expect(fields(idx.drizzle.get("posts"))).toEqual(["id", "title"]);
    expect(fields(idx.supabase.get("profiles"))).toEqual(["id", "api_key"]);
    expect([...idx.rlsTables]).toEqual(["profiles"]);
    expect(fields(idx.mongoose.get("Member"))).toEqual(["email", "password", "auth", "auth.resetToken"]);
    expect(idx.mongoose.get("Member")?.hidden).toEqual(["password"]);
    expect(idx.mongoose.get("Session")?.serializerFiltered).toBe(true);
    expect(fields(idx.sqlalchemy.get("User"))).toEqual(["id", "hashed_password", "recovery_code"]);
    expect(idx.sqlalchemy.get("User")?.hidden).toEqual(["recovery_code"]);
    expect(fields(idx.sqlalchemy.get("Hero"))).toEqual(["name", "id", "secret_name"]);
    expect(idx.pydantic.has("HeroBase")).toBe(true);
    expect(pydanticFields(idx, "UserCreate")).toEqual(["email", "password", "is_admin"]);
    expect(idx.count).toBe(8);
  });

  it("reports sensitive fields that are returned by default", () => {
    const idx = modelIndex(ctx());
    expect(sensitiveFields(idx.mongoose.get("Member")!)).toEqual(["auth.resetToken"]);
    expect(sensitiveFields(idx.sqlalchemy.get("User")!)).toEqual(["hashed_password"]);
    expect(sensitiveFields(idx.prisma.get("account")!)).toEqual(["apiKey"]);
    expect(sensitiveFields(idx.drizzle.get("posts")!)).toEqual([]);
  });
});

describe("helpers", () => {
  it("imports from tests/secor/ to a project file without the extension", () => {
    expect(importPathFrom("src/app.ts")).toBe("../../src/app");
    expect(importPathFrom("app/api/notes/[id]/route.ts")).toBe("../../app/api/notes/[id]/route");
    expect(importPathFrom("tests/secor/helpers/app.js")).toBe("./helpers/app");
  });

  it("reads the base type of FastAPI parameter annotations", () => {
    const tree = parseSource("def f(a: Annotated[UserIn, Body()], b: Optional[Item] = None, c: list[Item], d: Item | None = None, e: dict[str, Any], g: models.Item): pass\n", "python");
    const types = tree.rootNode.descendantsOfType("type").filter((t) => t?.parent?.type === "typed_parameter" || t?.parent?.type === "typed_default_parameter");
    expect(types.map((t) => pyTypeName(t!))).toEqual(["UserIn", "Item", "list", "Item", "dict", "Item"]);
    tree.delete();
  });
});

describe("template targets", () => {
  const unit = (ctx: ProjectContext, framework: UnitInfo["framework"], pkg?: string): UnitInfo => ({
    kind: "api",
    framework,
    root: "",
    files: ctx.files,
    manifests: pkg ? [parsePackageJson(pkg, "", "package.json")!] : [],
    backends: new Set(),
  });

  it("finds the Express app module and its export name", () => {
    const named = project({ "src/routes.ts": "export const x = 1;\n", "src/server.ts": 'import express from "express";\nexport const app = express();\napp.listen(3000);\n' });
    expect(expressApp(named, unit(named, "express"))).toEqual({ file: "src/server.ts", exportName: "app" });
    const cjs = project({ "app.js": 'const express = require("express");\nconst server = express();\nmodule.exports = server;\n' });
    expect(expressApp(cjs, unit(cjs, "express"))).toEqual({ file: "app.js", exportName: "default" });
    const unexported = project({ "index.js": 'const express = require("express");\nconst app = express();\napp.listen(3000);\n' });
    expect(expressApp(unexported, unit(unexported, "express"))).toEqual({ file: "index.js", exportName: "app" });
  });

  it("finds the FastAPI app module", () => {
    const ctx = project({ "src/app/__init__.py": "", "src/app/main.py": "from fastapi import FastAPI\n\napi = FastAPI()\n" });
    expect(fastapiApp(ctx, unit(ctx, "fastapi"))).toEqual({ module: "app.main", name: "api" });
  });

  it("picks the project's test runner for Express templates", () => {
    const ctx = project({ "index.js": "" });
    expect(jsTestFlag(ctx, unit(ctx, "express", JSON.stringify({ devDependencies: { jest: "29.7.0" } })))).toBe("jest");
    expect(jsTestFlag(ctx, unit(ctx, "express", JSON.stringify({ devDependencies: { vitest: "3.1.1", jest: "29.7.0" } })))).toBe("vitest");
    expect(jsTestFlag(ctx, unit(ctx, "express", JSON.stringify({ dependencies: { express: "4.21.2" } })))).toBe("vitest");
  });
});
