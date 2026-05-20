<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# optimization

## Purpose
Token-aware response shaping. Truncates, summarizes, and re-orders fields so large MSP responses fit within MCP token budgets while preserving the highest-signal data.

## Key Files

| File | Description |
|------|-------------|
| `index.ts` | `OptimizableObject`, `OptimizationStats`, smart truncation, field-level optimization for alarms / flows / etc. |

## For AI Agents

### Working In This Directory
- Optimization is **lossy by design** — never use it on data that will be fed back to the API.
- When adding a new entity type, add a dedicated field optimizer keyed on the shape — don't try to generalize across types.

### Common Patterns
- Word-boundary truncation; numeric estimates of token count rather than full encoding.

## Dependencies

### Internal
- `src/utils/timestamp.ts`, `src/types.ts`.

<!-- MANUAL: -->
