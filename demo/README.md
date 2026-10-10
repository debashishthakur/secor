# SECOR demo on the second-brain MCP server (brain-mcp)

Everything below runs locally. Demo state (scopes, servers, ledger, screenshots) lives in `demo/state/`
(gitignored) through `SECOR_HOME`, so your real `~/.secor` is not touched.

```sh
npm run build
export SECOR_HOME="$PWD/demo/state/secor-home"
secor() { node "$PWD/dist/cli.js" "$@"; }   # or `npm link` to get a global `secor`
```

## 1. Ship: check the server's own code

```sh
cd ~/Desktop/brain-mcp
secor init          # creates secor.config.yaml and .secor/.gitignore (nothing else is written)
secor ship          # summary; --json for the full RunResult
secor finding <id>  # explanation, fix, --test for a ready-made test
```

Result on 2026-10-10: Ship 79 ("Needs work" for Ship alone).
- High: `@modelcontextprotocol/sdk@1.30.0` has GHSA-6qxp-vccf-f47h (OAuth client credential leak; the advisory says servers built with the SDK are not affected). Fix: upgrade to 1.31.0.
- Medium: `sprintf-js@1.0.3` has GHSA-hp3w-g68c-fv3c (no fixed version yet).
- Advisory (not scored): `GET/POST /login`, `POST /consent`, `GET /healthz` have no login check — they are public by design. Declare them, with a reason, in `secor.config.yaml` (a human edit):

```yaml
public:
  - route: "GET /login"
    reason: "OAuth login page"
  - route: "POST /login"
    reason: "OAuth login form"
  - route: "POST /consent"
    reason: "OAuth consent form (needs a pending authorization request)"
  - route: "GET /healthz"
    reason: "Uptime probe"
```

The MCP endpoint (`app.all(cfg.http.path, bearer, …)`) is recognised as guarded by `requireBearerAuth`, and all 13 tools,
2 resources and 2 prompts are inventoried.

## 2. Connect: vet, scope and watch the server

```sh
secor connect list
secor connect vet second-brain                     # the hosted server: "incomplete · auth required" (OAuth protects it)
secor --cwd demo/project connect vet second-brain-local   # the published package in the Docker sandbox
secor --cwd demo/project connect add second-brain-local   # interactive: run it in a terminal
```

The sandboxed vet reads the real tool list (13 tools): verdict **ok**, one low note (`brain_delete` is a powerful tool,
left out of the allowlist by default).

## 3. Hooks: what happens on each tool call

```sh
node demo/hooks-demo.mjs     # sends Claude Code hook events through `secor hook pre|post|protect`
secor ledger
```

| Call | Decision |
|---|---|
| `brain_search` with a normal query | pass |
| `brain_capture` with an API key in the note | ask — `class:secret` |
| `brain_remember` with a customer's email | ask — `class:personal_data` |
| `brain_delete` on the scoped local server | ask — `tool-not-allowed` |
| `brain_capture` with code another server just returned | ask — `flow:codebase-memory-mcp` (24 fingerprints) |
| `brain_read` returning hidden instructions | warning added for the model |
| a call to the never-vetted `codebase-memory-mcp` | ask — `unvetted` |
| the agent editing `~/.secor/scopes.yaml` | deny |

## 4. Dashboard

```sh
cd ~/Desktop/brain-mcp && secor dashboard
```

Read-only, on 127.0.0.1, token-protected. To protect your real Claude Code sessions, run
`secor connect install-hooks` yourself (it backs up `~/.claude/settings.json` first).
