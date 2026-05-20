<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# setup

## Purpose
Jest setup hooks, referenced by `setupFilesAfterEach` in `jest.config.cjs`.

## Key Files

| File | Description |
|------|-------------|
| `jest-setup.ts` | Global before/after hooks: timezone pinning, console quieting, env defaults. |

## For AI Agents

### Working In This Directory
- Code here runs **once per test file** (after env). Keep it deterministic and side-effect light.

<!-- MANUAL: -->
