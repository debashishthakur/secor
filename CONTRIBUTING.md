# Contributing to SECOR

Thanks for helping. SECOR is a local security tool, so correctness and restraint matter more than breadth: a rule that cries wolf is worse than no rule.

## Ground rules (from the design doc)

`secor-design.md` is the spec and `DECISIONS.md` records every choice it left open. Before a change, skim both. The invariants in section 3 are non-negotiable:

- **Local only, no telemetry, no LLM in the engine.** The only network calls allowed are the ones in section 13.
- **Never write source files.** SECOR proposes patches; a human or the agent applies them.
- **Redaction everywhere.** No secret or personal data appears unredacted in any output.
- **Never say "secure".** Use the band labels in section 10.
- **Deterministic.** Same files + same rules version + same cached network data → identical findings, IDs, ordering and score.

If a change needs a decision the spec doesn't make, add a one-line entry to `DECISIONS.md` in the same PR.

## Development

```sh
npm ci --ignore-scripts   # SECOR parses with the committed WASM grammars; no native build needed
npm run build             # dist/cli.js and dist/probe.js
npm run typecheck
npm test                  # unit, fixture, inventory, CLI, Connect, Probe, MCP and dashboard tests
```

SECOR scans its own source clean (`node dist/cli.js gate --offline` passes). Keep it that way.

## Adding or changing a rule

1. One file per rule in `src/engine/rules/<pack>/`, registered in that pack's `index.ts`.
2. New rules ship as `maturity: "experimental"`. Promotion to `stable` happens only after the validation targets in section 14.3 are met, and is recorded in `DECISIONS.md`.
3. Every rule needs a **vulnerable** and a **clean** fixture under `test/fixtures/<ruleId>/`, for every framework it covers. `test/rules.test.ts` runs them automatically.
4. `why` text is fixed per rule and never uses "secure", "safe" or "passed" as a verdict. Evidence is the flagged code — pass it raw; the engine redacts and truncates it.
5. Never commit secret-shaped strings. Tests use the `__FAKE_*__` tokens (see `test/helpers/fixtures.ts`), which are substituted with generated values at test time.

## Dependencies

No new runtime dependency without a `DECISIONS.md` entry explaining why. SECOR aims for a small, auditable dependency tree and no native modules.

## Reporting security issues

Please report vulnerabilities privately — see [SECURITY.md](SECURITY.md), not a public issue.
