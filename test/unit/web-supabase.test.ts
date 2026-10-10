import { describe, expect, it } from "vitest";
import { buildSupabaseModel, isLiteralTrue, qkey, querySources, splitSql, tokenizeSql } from "../../src/engine/backends/supabase.js";

const model = (...files: string[]) => buildSupabaseModel(files.map((text, i) => ({ file: `m${i}.sql`, text })));
const table = (m: ReturnType<typeof model>, key: string) => m.tables.get(key);

describe("splitSql", () => {
  it("splits on top-level semicolons and reports statement start lines", () => {
    const st = splitSql("create table a (id int);\n\n-- note; not a statement\ncreate table b (id int);\n");
    expect(st.map((s) => s.line)).toEqual([1, 4]);
    expect(st[1]!.text.trim()).toBe("create table b (id int)");
  });

  it("ignores semicolons in strings, E-strings, quoted identifiers, comments and dollar-quoted bodies", () => {
    const sql = [
      "insert into t values ('a;b', E'it\\'s; ok', 'x''y;z');",
      'create table "we;ird" (id int);',
      "/* outer /* nested; */ still comment; */ select 1;",
      "create function f() returns void language plpgsql as $fn$ begin perform 1; end; $fn$;",
      "do $$ begin raise notice 'x;y'; end $$;",
      "select $1;",
    ].join("\n");
    const st = splitSql(sql);
    expect(st).toHaveLength(6);
    expect(st[2]!.text.trim()).toBe("select 1");
    expect(st[2]!.line).toBe(3);
    expect(st[3]!.text).toContain("$fn$ begin perform 1; end; $fn$");
  });

  it("blanks comments but keeps offsets and line breaks", () => {
    const src = "create /* c */ table x (id int); -- tail\n";
    const [s] = splitSql(src);
    expect(s!.text.length).toBe(src.indexOf(";"));
    expect(s!.text).not.toContain("/*");
  });

  it("tolerates unterminated strings and comments", () => {
    expect(() => splitSql("select 'oops; \n create table y (id int);")).not.toThrow();
    expect(() => splitSql("/* never closed")).not.toThrow();
    expect(splitSql("   \n  ")).toEqual([]);
  });
});

describe("tokenizeSql", () => {
  it("lowercases unquoted identifiers and keeps quoted ones", () => {
    const t = tokenizeSql('ALTER TABLE "Public"."Users" ENABLE row LEVEL security');
    expect(t.map((x) => `${x.type}:${x.value}`)).toEqual(["ident:alter", "ident:table", "qident:Public", "punct:.", "qident:Users", "ident:enable", "ident:row", "ident:level", "ident:security"]);
  });
});

describe("Supabase model", () => {
  it("tracks RLS across migrations in order", () => {
    const m = model("create table public.todos (id int);", "alter table public.todos enable row level security;");
    expect(table(m, "public.todos")?.rls).toBe(true);
    const m2 = model("create table todos (id int); alter table todos enable row level security;", "alter table if exists only public.todos disable row level security;");
    expect(table(m2, "public.todos")?.rls).toBe(false);
    expect(table(m2, "public.todos")?.disabledAt?.file).toBe("m1.sql");
  });

  it("handles quoted, case-sensitive and schema-qualified names", () => {
    const m = model('create table public."Users" (id int); alter table "public"."users" enable row level security; create table PUBLIC.Items (id int); alter table "public".items enable row level security;');
    expect(table(m, "public.Users")?.rls).toBe(false);
    expect(table(m, "public.items")?.rls).toBe(true);
  });

  it("keeps an existing table on CREATE TABLE IF NOT EXISTS and resets on a plain CREATE", () => {
    const m = model("create table t (id int); alter table t enable row level security; create table if not exists t (id int);");
    expect(table(m, "public.t")?.rls).toBe(true);
    const m2 = model("create table t (id int); alter table t enable row level security; drop table t; create table t (id int);");
    expect(table(m2, "public.t")?.rls).toBe(false);
  });

  it("follows drops, renames and schema moves, with their policies", () => {
    const m = model(
      "create table a (id int); create policy p on a for select using (true);",
      "alter table a rename to b; create table c (id int); alter table c set schema private; create table d (id int); drop table if exists d, e cascade;",
    );
    expect(m.tables.has("public.a")).toBe(false);
    expect(table(m, "public.b")).toBeDefined();
    expect([...m.policies.values()].map((p) => qkey(p.table))).toEqual(["public.b"]);
    expect(table(m, "private.c")).toBeDefined();
    expect(m.tables.has("public.d")).toBe(false);
  });

  it("reads policies: roles, command, permissive/restrictive, using and with check", () => {
    const m = model(
      `create policy "Ins" on public.posts as permissive for insert to anon, authenticated with check ( ( true ) );
       create policy "Res" on posts as restrictive for delete using (true);
       create policy all_p on posts using (auth.uid() = user_id) with check (true);`,
    );
    const ins = [...m.policies.values()].find((p) => p.name === "Ins")!;
    expect(ins).toMatchObject({ command: "insert", roles: ["anon", "authenticated"], permissive: true, using: null });
    expect(isLiteralTrue(ins.check)).toBe(true);
    expect([...m.policies.values()].find((p) => p.name === "Res")!.permissive).toBe(false);
    const all = [...m.policies.values()].find((p) => p.name === "all_p")!;
    expect(all).toMatchObject({ command: "all", roles: [] });
    expect(isLiteralTrue(all.using)).toBe(false);
  });

  it("applies ALTER POLICY and DROP POLICY", () => {
    const m = model("create policy p on t for select to anon using (true);", "alter policy p on t to authenticated using (auth.uid() = owner);", 'alter policy p on t rename to "q"; create policy z on t using (true); drop policy if exists z on public.t;');
    const ps = [...m.policies.values()];
    expect(ps.map((p) => p.name)).toEqual(["q"]);
    expect(ps[0]).toMatchObject({ roles: ["authenticated"], command: "select", using: "auth.uid() = owner" });
    expect(ps[0]!.loc.file).toBe("m1.sql");
  });

  it("reads views, security_invoker options and their sources", () => {
    const m = model(
      `create view public.v1 as select a.id from public.accounts a join profiles p on p.id = a.id, extra x;
       create or replace view v2 with (security_barrier, security_invoker = on) as select * from accounts;
       create view v3 with (security_invoker) as with recent as (select * from accounts) select * from recent, generate_series(1, 3);
       create materialized view if not exists mv as select * from accounts;
       create view v4 as select 1; alter view v4 set (security_invoker = true);
       create view v5 with (security_invoker = true) as select 1; alter view v5 reset (security_invoker);`,
    );
    const v = (k: string) => m.views.get(`public.${k}`)!;
    expect(v("v1").securityInvoker).toBe(false);
    expect(v("v1").sources.map(qkey)).toEqual(["public.accounts", "public.profiles", "public.extra"]);
    expect(v("v2").securityInvoker).toBe(true);
    expect(v("v3").securityInvoker).toBe(true);
    expect(v("v3").sources.map(qkey)).toEqual(["public.accounts"]);
    expect(v("mv")).toMatchObject({ materialized: true, securityInvoker: false });
    expect(v("v4").securityInvoker).toBe(true);
    expect(v("v5").securityInvoker).toBe(false);
  });

  it("does not create tables from function bodies or comments", () => {
    const m = model("create function f() returns void language plpgsql as $$ begin create table ghost (id int); end $$; -- create table c1 (id int);\n/* create table c2 (id int); */");
    expect([...m.tables.keys()]).toEqual([]);
  });

  it("treats a DO block that enables RLS dynamically as enabling it on existing public tables", () => {
    const m = model("create table a (id int); create table private.b (id int);", "do $$ declare r record; begin for r in select tablename from pg_tables where schemaname = 'public' loop execute format('alter table public.%I enable row level security', r.tablename); end loop; end $$;");
    expect(table(m, "public.a")?.rls).toBe(true);
    expect(table(m, "private.b")?.rls).toBe(false);
    const m2 = model("create table a (id int); create table b (id int);", "do $$ begin execute 'alter table public.a enable row level security'; end $$;");
    expect(table(m2, "public.a")?.rls).toBe(true);
    expect(table(m2, "public.b")?.rls).toBe(false);
  });

  it("isLiteralTrue ignores whitespace and parentheses only", () => {
    expect(isLiteralTrue(" ( ( TRUE ) ) ")).toBe(true);
    expect(isLiteralTrue("true and true")).toBe(false);
    expect(isLiteralTrue("1 = 1")).toBe(false);
    expect(isLiteralTrue(null)).toBe(false);
  });

  it("querySources ignores subquery parentheses but finds inner tables", () => {
    expect(querySources(tokenizeSql("select * from (select id from inner_t) s left join lateral (select 1) l on true")).map(qkey)).toEqual(["public.inner_t"]);
  });
});
