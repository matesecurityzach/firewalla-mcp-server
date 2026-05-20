<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# filters

## Purpose
Filter implementations and factory for the search engine. Each filter encapsulates how to evaluate one kind of clause against an entity (flow / alarm / rule / device).

## Key Files

| File | Description |
|------|-------------|
| `base.ts` | `Filter` interface + `FilterContext` (entity type, field mappings, helpers). Base class shared by all concrete filters. |
| `time.ts` | Temporal filters: absolute timestamps, relative offsets (`>1h`, `<7d`), ranges. |
| `index.ts` | `filterFactory` — dispatches AST nodes to the right filter implementation. The single export consumed by `src/tools/search.ts`. |

## For AI Agents

### Working In This Directory
- New filter? Implement `Filter` from `base.ts`, register it in the factory in `index.ts`, then add a parser node + grammar test in `tests/validation/query-syntax.test.ts`.
- Filters should be pure — given the same node + context + value, return the same boolean.

## Dependencies

### Internal
- `src/search/types.ts`, `src/search/parser.ts`, `src/validation/field-mapper.ts`.

<!-- MANUAL: -->
