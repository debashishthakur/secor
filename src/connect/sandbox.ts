// Docker sandbox for stdio MCP servers (spec sections 9.2 step 1 and 9.3 step 6).
// Environment variable VALUES are never placed on a docker command line: the container gets `-e NAME`, and the value
// travels in the docker CLI process environment. Nothing here logs or prints env values.

import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import type { DiscoveredServer } from "./discover.js";

/**
 * Writable scratch space on the read-only root. Docker mounts --tmpfs noexec with a 64 MB cap by default, which
 * stops npx/uvx from running the package they just installed under /root; exec is allowed, nosuid/nodev kept
 * (DECISIONS.md). No host directory is mounted, so the server still cannot read host files.
 */
export const TMPFS_TMP = "/tmp:rw,exec,nosuid,nodev,size=1g";
export const TMPFS_ROOT = "/root:rw,exec,nosuid,nodev,size=1g";

export const NODE_IMAGE = "node:22-slim";
export const UV_IMAGE = "ghcr.io/astral-sh/uv:python3.12-bookworm-slim";

/** Hardening flags shared by the vet container and the --apply-sandbox wrapper. */
const HARDENING = ["--cap-drop", "ALL", "--security-opt", "no-new-privileges"];

/** Basename of a command, without a Windows executable suffix. */
export function commandBase(command: string): string {
  const base = command.split(/[\\/]/).pop() ?? command;
  return base.replace(/\.(?:exe|cmd|bat)$/i, "");
}

/** Sandbox image for a stdio command (section 9.2), or null when there is none. */
export function sandboxImageFor(command: string): string | null {
  const base = commandBase(command);
  if (base === "node" || base === "npx" || base === "npm") return NODE_IMAGE;
  if (base === "uvx" || base === "uv" || base === "python" || base === "python3") return UV_IMAGE;
  return null;
}

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Names of configured env vars forwarded into a container. Invalid names are dropped (a name with "=" would put a
 * value on the command line), and so are PATH, HOME and DOCKER_*: they describe the host or would redirect the
 * docker CLI itself, and the container has its own PATH and HOME.
 */
export function forwardableEnvNames(env: Record<string, string> | undefined): string[] {
  return Object.keys(env ?? {})
    .filter((n) => ENV_NAME.test(n) && n !== "PATH" && n !== "HOME" && !n.startsWith("DOCKER_"))
    .sort();
}

export interface SandboxPlan {
  image: string;
  /** Command and arguments run inside the container. */
  command: string[];
  envNames: string[];
  /** Values for envNames, passed through the docker CLI process environment only. */
  envValues: Record<string, string>;
  entrypoint?: string;
  workdir?: string;
  user?: string;
  networkNone?: boolean;
}

// docker run options that take a value (the next argument, unless written as --opt=value).
const VALUE_FLAGS = new Set([
  "-a", "--attach", "--add-host", "--annotation", "--blkio-weight", "--cap-add", "--cap-drop", "--cgroup-parent", "--cgroupns",
  "--cidfile", "--cpu-shares", "-c", "--cpus", "--cpuset-cpus", "--cpuset-mems", "--detach-keys", "--device",
  "--device-cgroup-rule", "--dns", "--dns-option", "--dns-search", "--domainname", "-e", "--env", "--env-file",
  "--entrypoint", "--expose", "--gpus", "--group-add", "--health-cmd", "--health-interval", "--health-retries",
  "--health-start-period", "--health-timeout", "-h", "--hostname", "--ip", "--ip6", "--ipc", "--isolation", "-l",
  "--label", "--label-file", "--link", "--log-driver", "--log-opt", "--mac-address", "-m", "--memory",
  "--memory-reservation", "--memory-swap", "--memory-swappiness", "--mount", "--name", "--network", "--net",
  "--network-alias", "--oom-score-adj", "-p", "--publish", "--pid", "--pids-limit", "--platform", "--pull", "--restart",
  "--runtime", "--security-opt", "--shm-size", "--stop-signal", "--stop-timeout", "--storage-opt", "--sysctl", "--tmpfs",
  "-u", "--user", "--ulimit", "--userns", "--uts", "-v", "--volume", "--volume-driver", "--volumes-from", "-w", "--workdir",
]);
const BOOL_FLAGS = new Set([
  "-i", "--interactive", "-t", "--tty", "-d", "--detach", "--rm", "--init", "--read-only", "--privileged", "-P",
  "--publish-all", "--no-healthcheck", "--oom-kill-disable", "--sig-proxy", "--disable-content-trust", "-q", "--quiet",
]);

export interface ParsedDockerRun {
  image: string;
  command: string[];
  envNames: string[];
  /** Values written inline as `-e NAME=value` in the editor config. */
  inlineEnv: Record<string, string>;
  entrypoint?: string;
  workdir?: string;
  user?: string;
  networkNone: boolean;
}

/** Parse `docker run [options] IMAGE [COMMAND] [ARG...]` (args start at "run"); null when it cannot be understood. */
export function parseDockerRun(args: readonly string[]): ParsedDockerRun | null {
  if (args[0] !== "run") return null;
  const out: ParsedDockerRun = { image: "", command: [], envNames: [], inlineEnv: Object.create(null) as Record<string, string>, networkNone: false };
  let i = 1;
  for (; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--") {
      i++;
      break;
    }
    if (!a.startsWith("-") || a === "-") break;
    const eq = a.startsWith("--") ? a.indexOf("=") : -1;
    const flag = eq > 0 ? a.slice(0, eq) : a;
    if (BOOL_FLAGS.has(flag)) continue;
    if (/^-[itdPq]{2,}$/.test(a)) continue; // clustered short booleans such as -it
    if (!VALUE_FLAGS.has(flag)) return null;
    let value: string;
    if (eq > 0) value = a.slice(eq + 1);
    else {
      if (i + 1 >= args.length) return null;
      value = args[++i]!;
    }
    if (flag === "-e" || flag === "--env") {
      const k = value.indexOf("=");
      const name = k >= 0 ? value.slice(0, k) : value;
      if (!ENV_NAME.test(name)) return null;
      if (!out.envNames.includes(name)) out.envNames.push(name);
      if (k >= 0) out.inlineEnv[name] = value.slice(k + 1);
    } else if (flag === "--entrypoint") out.entrypoint = value;
    else if (flag === "-w" || flag === "--workdir") out.workdir = value;
    else if (flag === "-u" || flag === "--user") out.user = value;
    else if ((flag === "--network" || flag === "--net") && value === "none") out.networkNone = true;
  }
  const image = args[i];
  if (!image || image.startsWith("-")) return null;
  out.image = image;
  out.command = args.slice(i + 1);
  out.envNames.sort();
  return out;
}

/** What the vet sandbox runs for a stdio server, or why it cannot. */
export function sandboxPlan(server: DiscoveredServer): SandboxPlan | { error: string } {
  const env = server.env ?? {};
  if (!server.command) return { error: "no command configured" };
  if (commandBase(server.command) === "docker") {
    const parsed = parseDockerRun(server.args ?? []);
    if (!parsed) return { error: "no sandbox image for this command" };
    const names = [...new Set([...parsed.envNames, ...forwardableEnvNames(env)])].filter((n) => n !== "PATH" && n !== "HOME" && !n.startsWith("DOCKER_")).sort();
    const envValues: Record<string, string> = Object.create(null) as Record<string, string>;
    for (const n of names) {
      if (Object.hasOwn(env, n)) envValues[n] = env[n]!;
      else if (Object.hasOwn(parsed.inlineEnv, n)) envValues[n] = parsed.inlineEnv[n]!;
    }
    return {
      image: parsed.image,
      command: parsed.command,
      envNames: names,
      envValues,
      ...(parsed.entrypoint !== undefined ? { entrypoint: parsed.entrypoint } : {}),
      ...(parsed.workdir !== undefined ? { workdir: parsed.workdir } : {}),
      ...(parsed.user !== undefined ? { user: parsed.user } : {}),
      networkNone: parsed.networkNone,
    };
  }
  const image = sandboxImageFor(server.command);
  if (!image) return { error: "no sandbox image for this command" };
  const names = forwardableEnvNames(env);
  const envValues: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const n of names) envValues[n] = env[n]!;
  return { image, command: [commandBase(server.command), ...(server.args ?? [])], envNames: names, envValues };
}

export function vetContainerName(): string {
  return `secor-vet-${randomBytes(6).toString("hex")}`;
}

/** `docker run` arguments for vetting (no host directories mounted). Contains env names only, never values. */
export function vetDockerArgs(containerName: string, plan: SandboxPlan): string[] {
  const args = ["run", "--rm", "-i", "--init", "--name", containerName, "--read-only", "--tmpfs", TMPFS_TMP, "--tmpfs", TMPFS_ROOT, ...HARDENING, "--pids-limit", "512"];
  if (plan.networkNone) args.push("--network", "none");
  for (const n of plan.envNames) args.push("-e", n);
  if (plan.entrypoint !== undefined) args.push("--entrypoint", plan.entrypoint);
  if (plan.workdir !== undefined) args.push("-w", plan.workdir);
  if (plan.user !== undefined) args.push("-u", plan.user);
  args.push(plan.image, ...plan.command);
  return args;
}

/** Validate and normalise sandbox mounts: absolute, no ":" or "," (docker -v separators). */
export function checkMounts(mounts: readonly string[]): { mounts: string[]; errors: string[] } {
  const out: string[] = [];
  const errors: string[] = [];
  for (const m of mounts) {
    if (!m.startsWith("/")) errors.push(`mount "${m}" is not an absolute path`);
    else if (/[:,\n]/.test(m)) errors.push(`mount "${m}" contains ":" or ","`);
    else out.push(m.length > 1 ? m.replace(/\/+$/, "") : m);
  }
  return { mounts: [...new Set(out)], errors };
}

/** The editor-config wrapper of section 9.3 step 6: read-only mounts from the scope, env names only. */
export function wrapperArgs(plan: SandboxPlan, mounts: readonly string[]): string[] {
  const args = ["run", "--rm", "-i", "--init", "--read-only", "--tmpfs", TMPFS_TMP, "--tmpfs", TMPFS_ROOT, ...HARDENING];
  if (plan.networkNone) args.push("--network", "none");
  for (const m of mounts) args.push("-v", `${m}:${m}:ro`);
  for (const n of plan.envNames) args.push("-e", n);
  if (plan.entrypoint !== undefined) args.push("--entrypoint", plan.entrypoint);
  if (plan.workdir !== undefined) args.push("-w", plan.workdir);
  if (plan.user !== undefined) args.push("-u", plan.user);
  args.push(plan.image, ...plan.command);
  return args;
}

/** Quote one argument for display in a POSIX shell. */
export function shellQuote(arg: string): string {
  return /^[A-Za-z0-9_@%+=:,./-]+$/.test(arg) ? arg : `'${arg.replace(/'/g, `'\\''`)}'`;
}

// ---------------------------------------------------------------- docker processes

const DOCKER_ENV_KEYS = ["HOME", "LOGNAME", "PATH", "SHELL", "TERM", "USER", "TMPDIR", "XDG_RUNTIME_DIR", "SystemRoot", "APPDATA", "LOCALAPPDATA", "USERPROFILE", "ProgramData"];

/** Environment for the docker CLI: what it needs to find its daemon, plus host DOCKER_* settings. */
export function dockerClientEnv(): Record<string, string> {
  const env: Record<string, string> = Object.create(null) as Record<string, string>;
  for (const [k, v] of Object.entries(process.env)) {
    if (v === undefined || v.startsWith("()")) continue;
    if (DOCKER_ENV_KEYS.includes(k) || k.startsWith("DOCKER_")) env[k] = v;
  }
  return env;
}

interface RunResult {
  code: number | null;
  stdout: string;
  timedOut: boolean;
}

/** Run `docker <args>` with no stdin and captured (never printed) output. */
export function runDocker(args: string[], timeoutMs: number): Promise<RunResult> {
  return new Promise((resolvePromise) => {
    let stdout = "";
    let timedOut = false;
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn("docker", args, { env: dockerClientEnv(), stdio: ["ignore", "pipe", "ignore"], windowsHide: true });
    } catch {
      resolvePromise({ code: null, stdout: "", timedOut: false });
      return;
    }
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    timer.unref();
    child.stdout?.on("data", (d: Buffer) => {
      if (stdout.length < 65536) stdout += d.toString("utf8");
    });
    child.on("error", () => {
      clearTimeout(timer);
      resolvePromise({ code: null, stdout, timedOut });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolvePromise({ code, stdout, timedOut });
    });
  });
}

let dockerAvailableCache: Promise<boolean> | null = null;

/** True when a docker daemon answers (cached for the process). */
export function dockerAvailable(): Promise<boolean> {
  dockerAvailableCache ??= runDocker(["version", "--format", "{{.Server.Version}}"], 15_000).then((r) => r.code === 0 && r.stdout.trim() !== "");
  return dockerAvailableCache;
}

/** For tests: forget the cached docker availability. */
export function resetDockerCache(): void {
  dockerAvailableCache = null;
}

/** Make sure the image is present, pulling it if needed (before the vet timeout starts). */
export async function ensureImage(image: string, timeoutMs = 600_000): Promise<boolean> {
  if (image.startsWith("-")) return false;
  const inspect = await runDocker(["image", "inspect", "--format", "{{.Id}}", image], 30_000);
  if (inspect.code === 0) return true;
  const pull = await runDocker(["pull", "--quiet", image], timeoutMs);
  return pull.code === 0;
}

/** Always run after a vet: removes the named container if it still exists. */
export async function removeContainer(name: string): Promise<void> {
  await runDocker(["rm", "-f", name], 30_000);
}
