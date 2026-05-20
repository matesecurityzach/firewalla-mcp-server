<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# .githooks

## Purpose
Local-only git hooks. Installed into `.git/hooks/` by running `npm run setup:hooks` (which invokes `setup-hooks.sh`).

## Key Files

| File | Description |
|------|-------------|
| `pre-commit` | Pre-commit gate (format/lint/typecheck — see the file for the exact wiring). |

## For AI Agents

### Working In This Directory
- Hooks here are not active until `setup-hooks.sh` symlinks them into `.git/hooks/`.
- Keep them fast; a slow pre-commit is the fastest path to `--no-verify` becoming reflex.

<!-- MANUAL: -->
