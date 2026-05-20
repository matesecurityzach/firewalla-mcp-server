<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# tools (tests)

## Purpose
Tests for `src/tools/` wiring. Individual handler-class tests live alongside their `.test.ts` files; this folder covers registry/setup glue.

## Key Files

| File | Description |
|------|-------------|
| `setup.test.ts` | `setupTools()` registers the expected handlers; dispatcher resolves names correctly. |

## For AI Agents

### Working In This Directory
- When you add a tool, you almost always want a unit test for the handler class itself in addition to (not instead of) any wiring asserts here.

<!-- MANUAL: -->
