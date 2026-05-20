<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# config (tests)

## Purpose
Tests + shared fixtures for `src/config/`.

## Key Files

| File | Description |
|------|-------------|
| `limits.test.ts` | Asserts numeric ceilings (pagination, response sizes). |
| `security.test.ts` | `SecurityManager` behavior. |
| `test-config.ts` | Fixture: lightweight config object for other suites to import. |
| `test-thresholds.ts` | Shared numeric thresholds used across tests. |

## For AI Agents

### Working In This Directory
- `test-config.ts` and `test-thresholds.ts` are imported by other suites — changes here can ripple. Run the full suite, not just this folder.

<!-- MANUAL: -->
