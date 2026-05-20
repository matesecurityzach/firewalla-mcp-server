<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# utils (tests)

## Purpose
Pure-function tests for `src/utils/`. One file per util.

## Key Files

| File | Description |
|------|-------------|
| `alarm-id-validation.test.ts` | Alarm-ID format checks. |
| `data-normalizer.test.ts` | Response shape normalization. |
| `data-validator.test.ts` | Runtime data shape checks. |
| `env.test.ts` | Required + optional env var parsing, transport config. |
| `field-normalizer.test.ts` | Field-name canonicalization. |
| `null-safety.test.ts` | Defensive accessors. |
| `simple-boolean-translator.test.ts` | Fast-path boolean-field translation. |
| `timestamp.test.ts` | ISO ↔ Unix conversions and bounds. |
| `unified-response.test.ts` | Tool-response envelope shape. |

## For AI Agents

### Working In This Directory
- These are the highest-leverage tests — they run on every commit via `npm run test:quick`.

<!-- MANUAL: -->
