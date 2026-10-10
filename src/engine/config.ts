// Project configuration (spec sections 6.1 and 6.2). Unknown keys are an error with a clear message.

import { existsSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

const reason = z.string().trim().min(1, "a non-empty reason is required");
const ROUTE = /^(\*|GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS) (\/\S*)$/;

const PublicEntry = z.union([
  z.strictObject({
    route: z.string().regex(ROUTE, 'route must look like "<METHOD> <path>", for example "GET /api/health" (METHOD may be "*")'),
    reason,
  }),
  z.strictObject({ action: z.string().regex(/^[^#]+#[A-Za-z_$][\w$]*$/, 'action must look like "<file>#<export>"'), reason }),
  z.strictObject({ mcpServer: z.string().min(1), reason }),
]);

export const ProjectConfigSchema = z.strictObject({
  version: z.literal(1),
  project: z.string().min(1).optional(),
  packs: z.union([z.literal("auto"), z.array(z.enum(["api", "mcp", "web"]))]).default("auto"),
  exclude: z.array(z.string().min(1)).default([]),
  public: z.array(PublicEntry).default([]),
  auth: z
    .strictObject({
      guards: z.array(z.string().min(1)).default([]),
      ownershipHelpers: z.array(z.string().min(1)).default([]),
    })
    .default({ guards: [], ownershipHelpers: [] }),
  rateLimit: z.strictObject({ helpers: z.array(z.string().min(1)).default([]) }).default({ helpers: [] }),
  mcp: z.strictObject({ deployment: z.enum(["auto", "local", "remote"]).default("auto") }).default({ deployment: "auto" }),
  gate: z.strictObject({ failOn: z.enum(["critical", "high"]).default("critical") }).default({ failOn: "critical" }),
  network: z.boolean().default(true),
});

export type ProjectConfig = z.infer<typeof ProjectConfigSchema>;
export type PublicEntry = z.infer<typeof PublicEntry>;

export const IgnoreFileSchema = z.strictObject({
  version: z.literal(1),
  ignores: z
    .array(
      z.strictObject({
        finding: z.string().regex(/^[a-z0-9-]+-[0-9a-f]{12}$/, "finding must be a finding ID such as api-missing-auth-3f9a1c2b7d4e"),
        reason,
        by: z.string().trim().min(1, "by is required"),
        date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, "date must be YYYY-MM-DD"),
      }),
    )
    .default([]),
});

export type IgnoreFile = z.infer<typeof IgnoreFileSchema>;

export function formatZodError(file: string, err: z.ZodError): string {
  const lines = err.issues.map((i) => {
    const where = i.path.length ? i.path.join(".") : "(top level)";
    if (i.code === "unrecognized_keys") return `${file}: ${where}: unknown key${i.keys.length > 1 ? "s" : ""} ${i.keys.map((k) => `"${k}"`).join(", ")}`;
    if (i.code === "invalid_union") return `${file}: ${where}: expected one of: route, action or mcpServer, each with a non-empty reason`;
    return `${file}: ${where}: ${i.message}`;
  });
  return lines.join("\n");
}

export function parseYamlFile(path: string, label: string): unknown {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (e) {
    throw new ConfigError(`${label}: cannot read file (${(e as Error).message})`);
  }
  try {
    return parseYaml(text, { prettyErrors: true, maxAliasCount: 50 }) ?? {};
  } catch (e) {
    throw new ConfigError(`${label}: invalid YAML: ${(e as Error).message.split("\n")[0]}`);
  }
}

export function validate<T>(schema: z.ZodType<T>, raw: unknown, label: string): T {
  const res = schema.safeParse(raw);
  if (!res.success) throw new ConfigError(formatZodError(label, res.error));
  return res.data;
}

export const CONFIG_FILE = "secor.config.yaml";
export const IGNORE_FILE = ".secor/ignore.yaml";

export function defaultConfig(): ProjectConfig {
  return ProjectConfigSchema.parse({ version: 1 });
}

export function loadProjectConfig(root: string): ProjectConfig {
  const path = join(root, CONFIG_FILE);
  if (!existsSync(path)) return defaultConfig();
  return validate(ProjectConfigSchema, parseYamlFile(path, CONFIG_FILE), CONFIG_FILE);
}

export function loadIgnoreFile(root: string): IgnoreFile {
  const path = join(root, IGNORE_FILE);
  if (!existsSync(path)) return { version: 1, ignores: [] };
  return validate(IgnoreFileSchema, parseYamlFile(path, IGNORE_FILE), IGNORE_FILE);
}

/** Project name: config "project", else package.json "name", else the folder name. */
export function projectName(root: string, config: ProjectConfig): string {
  if (config.project) return config.project;
  try {
    const pkg = JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as { name?: unknown };
    if (typeof pkg.name === "string" && pkg.name) return pkg.name;
  } catch {
    // no package.json
  }
  return basename(root);
}

/** Parse a public route entry ("GET /api/health"). */
export function parsePublicRoute(route: string): { method: string; path: string } {
  const m = ROUTE.exec(route)!;
  return { method: m[1]!, path: m[2]! };
}

export const INIT_TEMPLATE = `# SECOR project configuration (spec section 6.1). Edited by humans only.
version: 1
# project: my-app            # default: package.json "name", else the folder name
packs: auto                   # "auto" or a list from: api, mcp, web
exclude: []                   # extra globs to skip
public: []                    # entry points meant to be reachable without auth, each with a reason:
#  - route: "GET /api/health"
#    reason: "Uptime probe"
#  - action: "app/actions.ts#subscribe"
#    reason: "Newsletter signup"
#  - mcpServer: "src/server.ts"
#    reason: "Public docs search, no user data"
auth:
  guards: []                  # extra function, middleware or dependency names that count as auth
  ownershipHelpers: []        # extra function names that count as ownership checks
rateLimit:
  helpers: []                 # extra function names that count as rate limiting
mcp:
  deployment: auto            # auto | local | remote
gate:
  failOn: critical            # critical | high
network: true                 # false = offline mode
`;
