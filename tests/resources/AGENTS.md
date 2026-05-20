<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# resources (tests)

## Purpose
Tests for `src/resources/`. Covers `setupResources` registration (both `ListResources` and `ReadResource` handlers), `RESOURCE_CATALOG` parity, and the URI dispatch path for each live and reference URI.

## Key Files

| File | Description |
|------|-------------|
| `index.test.ts` | Asserts both `ListResourcesRequestSchema` and `ReadResourceRequestSchema` handlers are registered, that `ListResources` returns all 9 URIs (live + reference), and that each `firewalla://reference/*` URI plus `firewalla://boxes` resolves with the expected payload shape. |

## For AI Agents

### Working In This Directory
- When you add a resource URI, add a `case` test here that walks the read handler and asserts the JSON-decoded payload shape. The `buildMockServer` helper at the top of the file captures registered handlers by schema reference so you can call them directly.

<!-- MANUAL: -->
