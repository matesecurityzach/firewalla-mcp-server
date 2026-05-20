<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# tools (tests)

## Purpose
Tests for `src/tools/` wiring. Registry/setup glue tests live here; per-handler unit tests live under `handlers/`.

## Key Files

| File | Description |
|------|-------------|
| `setup.test.ts` | `setupTools()` registers the expected handlers; dispatcher resolves names correctly. |
| `registry-schema-parity.test.ts` | Enforces the registry ↔ `ListTools` schema contract: every registered handler has a matching schema entry in `src/server.ts` and vice versa. Also asserts the expected total tool count (currently 37). Run after any tool addition or removal. |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `handlers/` | Per-handler unit tests (see `handlers/AGENTS.md`). Currently covers the investigation composite tools and the `generate_*` report tools. |

## For AI Agents

### Working In This Directory
- When you add a tool, write a unit test for the handler class itself under `handlers/` in addition to (not instead of) any wiring asserts here.
- If you change the total tool count, the assertion in `registry-schema-parity.test.ts` (`registers exactly 37 tools`) must be updated in the same PR.

<!-- MANUAL: -->
