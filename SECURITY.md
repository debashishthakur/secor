# Security policy

SECOR is a security tool that reads source code, runs untrusted MCP servers to vet them, and (opt-in) sends requests to a target you own. A flaw in SECOR could leak data it was meant to protect, so reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability. Report it privately through GitHub:

1. Go to the [Security tab](https://github.com/debashishthakur/secor/security) of this repository.
2. Choose **Report a vulnerability**.
3. Describe the issue, how to reproduce it, and the impact you expect.

You should get a first response within a week. Once a fix is ready, the advisory is published with credit to you, unless you prefer to stay anonymous.

## In scope

The security of SECOR itself — the ways it could betray the trust in its own invariants (`secor-design.md` section 3):

- **Redaction gaps** — a secret, credential or personal-data format that reaches stdout, JSON, the ledger, the dashboard or an MCP tool result unmasked (`src/engine/redact.ts`, `src/engine/detectors/`).
- **Code execution while scanning** — a project that makes SECOR run code when it reads or parses it (e.g. through a crafted `.git/config`; see the git hardening in `src/engine/files.ts`).
- **Vetting sandbox escape** — a server that reads host files or escapes the container during `connect vet` (`src/connect/vet.ts`, `src/connect/sandbox.ts`).
- **Hook failures** — a hook that returns `permissionDecision: "allow"`, breaks the editor, or writes a policy file (hooks are humans-only, fail-open; `src/connect/hooks.ts`).
- **Probe ownership bypass** — any way to make Probe send traffic to a target that did not pass the ownership check, including DNS rebinding and cloud-metadata addresses (`src/probe/scope-guard.ts`, `src/probe/addresses.ts`).
- **Dashboard** — anything that lets a page other than the local dashboard read `/api/summary`, or any state-changing route (`src/dashboard/server.ts`).
- **Network policy** — any request to a destination not listed in `secor-design.md` section 13.

## Out of scope

- Findings SECOR reports in *your* code (that's the tool working — fix them in your project).
- False positives or false negatives in rules — please file those as normal issues.
- The deliberately vulnerable fixtures under `test/fixtures/` and the demo servers under `test/connect/`.
