<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# search (tests)

## Purpose
Tests focused on boolean field translation, the entry point most likely to regress when the query grammar changes.

## Key Files

| File | Description |
|------|-------------|
| `boolean-field-translator.test.ts` | Behavior cases for `src/search/boolean-field-translator.ts`. |
| `boolean-field-translator-coverage.test.ts` | Coverage-padding cases for edge inputs. |

## For AI Agents

### Working In This Directory
- Parser-level cases live in `tests/validation/query-syntax.test.ts`. Don't duplicate them here.

<!-- MANUAL: -->
