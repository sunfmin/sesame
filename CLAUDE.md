# sesame

Sign in to SaaS APIs that have no CLI of their own and call their REST APIs
with the stored token. See `README.md`.

`./gate.sh` (fmt, clippy, tests via `slimfit check`) must pass before anything lands.

Each change follows `slimfit next`'s loop and the rule for its mutants in `slimfit help factorium` (run `slimfit help` for the rest).

## Agent skills

### Issue tracker

Issues live in factorium's local tracker (`factorium issue … sesame`). See `docs/agents/issue-tracker.md`.

### Domain docs

single-context: root `GLOSSARY.md` + `docs/adr/`, created when first needed. See `docs/agents/domain.md`.
