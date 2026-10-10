## What this changes

<!-- One or two sentences. Link the issue it closes, if any. -->

## Checklist

- [ ] `npm run typecheck` and `npm test` pass locally
- [ ] New or changed rules have a vulnerable **and** a clean fixture (`test/fixtures/<ruleId>/`)
- [ ] No secret-shaped strings committed (use the `__FAKE_*__` tokens in tests)
- [ ] A choice the spec left open is recorded in `DECISIONS.md`
- [ ] No new runtime dependency without a `DECISIONS.md` entry
