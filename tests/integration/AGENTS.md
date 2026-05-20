<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# integration

## Purpose
Cross-module integration tests. Run by `npm run test:integration` (matches `--testPathPatterns=integration`).

## Key Files

| File | Description |
|------|-------------|
| `boolean-syntax.test.ts` | End-to-end boolean-query handling across parser + filters + tool execution. |

## For AI Agents

### Working In This Directory
- Mock HTTP with `nock`; do not call the live MSP API.
- Setting `TEST_ENV=integration` is what `npm run test:integration` does — match that env when reproducing locally.

<!-- MANUAL: -->
