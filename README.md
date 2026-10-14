# SECOR — Security Context Orchestrator

[![CI](https://github.com/debashishthakur/secor/actions/workflows/ci.yml/badge.svg)](https://github.com/debashishthakur/secor/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%E2%89%A520-5fa04e?logo=node.js&logoColor=white)](package.json)
[![M8ven Score](https://m8ven.ai/badge/mcp/debashishthakur-secor-11yvps?v=2b15c27e6b90e19a8232cb11136f0f7c&variant=verified)](https://m8ven.ai/mcp/debashishthakur-secor-11yvps?s=readme)

SECOR is a local security tool for developers who build with AI.

- **SECOR Ship** checks the API endpoints, MCP servers and websites you build, before you deploy them.
- **SECOR Connect** protects your data from the third-party MCP servers you connect to your AI agent.
- **SECOR Probe** (opt-in) confirms suspected flaws against your own staging deployment, read-only.
- A local, read-only **dashboard** shows a score and a fixed set of metrics for both parts.

SECOR finds common, known mistakes, explains why they matter, and proposes fixes. It is honest about what it did not
check, and it never claims a system is "secure": scores count known issues in the checks it ran.

Everything runs on your machine. SECOR sends no source code, file contents, tool arguments or tool outputs anywhere,
has no telemetry, and makes no LLM calls. The only network destinations are listed under [Network](#network).

> Design and normative behaviour: [`secor-design.md`](secor-design.md). Choices where the spec was silent: [`DECISIONS.md`](DECISIONS.md).

## Install

Requires Node.js 20 or later. Python does not need to be installed (Python projects are parsed with tree-sitter).

```sh
npm install -g secor        # once published
# from a checkout:
npm ci && npm run build && npm link
```

## Quick start

```sh
secor init                 # creates secor.config.yaml and .secor/.gitignore
secor ship                 # checks the project and prints a summary (--json for the full RunResult)
secor finding <id>         # explains one finding (--patch, --test for the proposed patch / test)
secor gate --fail-on high  # for CI: exit 1 when counted findings reach the severity
secor dashboard            # local read-only dashboard at 127.0.0.1

secor connect list         # MCP servers found in Claude Code, Cursor, Claude Desktop and VS Code configs
secor connect vet <name>   # reads a server's tool list in a Docker sandbox and checks it for risky patterns
secor connect add <name>   # interactive: vet, choose allowed tools and forbidden data, record the scope
secor connect install-hooks  # Claude Code hooks that check each MCP tool call
secor ledger               # what the hooks decided (metadata only)
```

## What Ship checks

25 rules in four packs, for TypeScript/JavaScript and Python projects using Express, Next.js, FastAPI, Vite (React),
the official MCP SDKs, Supabase and Firebase:

| Pack | Rules |
|---|---|
| core | secrets in code or git history · vulnerable dependencies (OSV) · hallucinated / brand-new packages · errors returned to callers · paid APIs without a rate limit |
| api | missing auth · missing ownership check · whole rows returned · mass assignment · unvalidated input · SQL built from strings · unsigned webhooks · any-origin CORS with credentials · auth only in Next.js middleware |
| mcp | remote server without auth · client token passed through · tools with unrestricted file or command access · local HTTP server reachable beyond the machine · weak session IDs |
| web | secrets shipped to the browser · database open to the public (Supabase RLS, Firebase rules) · role checks only in the UI · session cookie flags · security headers · debug features in production |

Every finding has a stable ID, redacted evidence, a fixed explanation and a fix. Some come with a unified-diff patch
(`secor finding <id> --patch`) or a test template that proves the fix (`--test`). **SECOR never edits your source files.**

### Rule maturity

Every rule starts as **experimental** and is promoted to **stable** only after it meets the validation targets in
spec section 14.3. Only stable rules affect the score and the gate; experimental and advisory findings are always
listed, under "Advisory (not scored)". See [Validation](#validation) for the current numbers.

## Score

`overall = min(Ship, Connect)`, each 0–100 (scoring version 1, spec section 10):

| Band | Meaning |
|---|---|
| 0–49 · Fix before deploy | a counted critical finding, or many issues |
| 50–79 · Needs work | a counted high finding, or several smaller ones |
| 80–100 · No critical or high issues known | in the checks SECOR ran |

Coverage (the share of applicable checks that ran) is shown beside every score, along with what SECOR could not check.
This score counts known issues in the checks SECOR ran. It does not measure how hard your system is to attack.

## Connect

SECOR works beside your agent, at four moments: before connecting (**vet**), at setup (**scope** and **sandbox**),
while the agent works (**hooks**), and afterwards (**ledger** and **drift**). It never relays traffic.

Limits (spec 9.8):
- Exact and near-exact copies of sensitive data are caught. Reworded or encoded data often is not.
- A local MCP server is a program on your machine. Only the sandbox limits what it can read on its own.
- Only Claude Code gets per-call checks in v1.

## Probe (opt-in)

`secor probe --target <staging url> --i-own-this-target` sends a small fixed set of read-only requests to a target
you have proven you own (loopback/private address, a token file, a DNS TXT record, or your host's API). Never point it
at production. No MCP tool, hook, gate or CI job can start it. Limits (spec 9A.9): a silent Probe run is not proof of
safety; it tests only the one target you supply; it is read-only, so write-side flaws are covered by Ship and the
generated tests.

## Claude Code plugin and MCP server

The repository is also a Claude Code plugin (`.claude-plugin/plugin.json`, `hooks/hooks.json`, `.mcp.json`,
`skills/secor/SKILL.md`). The MCP server (`secor mcp`, stdio) exposes `ship_check`, `ship_results`, `ship_finding`,
`ship_verify`, `connect_status`, `connect_vet`, `ledger_summary` and `open_dashboard`. No tool can change policy files,
and none can start Probe.

## Network

| Destination | Used by | Sends | Disabled by |
|---|---|---|---|
| `api.osv.dev` | vulnerable-dependency | package names, ecosystems, versions | `--offline` / `network: false` |
| `registry.npmjs.org`, `api.npmjs.org`, `pypi.org` | hallucinated-package | package names | same |
| the URL of an HTTP MCP server you vet | Connect | MCP initialize / list requests with its configured headers | not vetting |
| Docker image registries | the vet sandbox | image names | not using the sandbox |
| your one authorized Probe target | Probe | the fixed non-destructive checks | not running `secor probe` |

## Validation

First validation round (2026-10-10, details and method in [`DECISIONS.md`](DECISIONS.md#validation-and-promotion-m7-2026-10-10)):
9 public repositories — OWASP Juice Shop and damn-vulnerable-MCP-server (deliberately vulnerable), chatbot-ui,
saas-starter, full-stack-fastapi-template, the Express RealWorld app, and the official MCP servers, Python SDK and
fastmcp examples. This is smaller than the ~20 repositories per kind the spec asks for, so only rules with enough
evidence were promoted.

| Rule | Findings | False alarms | Maturity |
|---|---|---|---|
| core/secrets | 42 | 1 (2%) | stable |
| core/vulnerable-dependency | 83 | 0 | stable |
| core/paid-api-limit | 11 | 0 | stable |
| web/security-headers | 12 | 0 | stable |
| mcp/tool-scope | 19 | 0 | stable |
| api/missing-auth | 87 | 6 (7%); 80% are public by design until declared in `secor.config.yaml` | experimental |
| mcp/local-binding | 9 | ≤ 1 | experimental (< 10 findings) |
| api/unvalidated-input · mcp/auth-required · web/cookie-flags · api/sql-injection-risk · core/error-leakage | 1–5 each | 0 | experimental (too few findings) |
| mcp/session-handling | 1 | 1 (test mock) | experimental |
| other rules | 0 | – | experimental |

Known misses are listed per rule under "Limitations" in each area's section of `DECISIONS.md`.

Connect: hook catch rate for verbatim planted secrets, credentials and personal data 100/100; false blocks on 250
legitimate calls 0; hook engine time p99 6.5 ms (target ≤ 50 ms); whole hook process p95 70 ms.

## Development

```sh
npm ci
npm run typecheck
npm test            # unit, fixture, inventory, CLI, Connect, Probe, MCP and dashboard tests
npm run build       # dist/cli.js and dist/probe.js
```

Licence: Apache-2.0.
