<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# search

## Purpose
Query language for the `search_*` tools. Parses Firewalla-style expressions (`type:1 AND source_ip:192.168.* NOT resolved:true`) into an AST, then applies filters either client-side or by translating to MSP query parameters.

## Key Files

| File | Description |
|------|-------------|
| `index.ts` | Public surface: high-level search execution that ties parser + filters + result shaping. |
| `parser.ts` | Tokenizer + recursive-descent parser for the search grammar. |
| `types.ts` | AST node types, `SearchParams`, `SearchResult`, filter context types. |
| `boolean-field-translator.ts` | Maps boolean-field shorthand (e.g., `blocked:true`) to canonical filter clauses. |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `filters/` | Filter implementations (time, base) + factory (see `filters/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- Grammar changes ripple into `docs/query-syntax-guide.md` and the regression cases in `tests/validation/query-syntax.test.ts`.
- The parser is intentionally permissive on whitespace and case for field names — preserve that.

### Testing Requirements
- See `tests/search/` and `tests/validation/query-syntax.test.ts`.

### Common Patterns
- Parser produces nodes; filter factory matches nodes to filter objects with `apply(value, ctx)`.

## Dependencies

### Internal
- `src/validation/field-mapper.ts` for entity-aware field resolution.

<!-- MANUAL: -->
