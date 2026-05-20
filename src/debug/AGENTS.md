<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# debug

## Purpose
Runtime introspection: assembles a `DebugInfo` snapshot of uptime, memory, cache state, and metrics for diagnostic surfaces.

## Key Files

| File | Description |
|------|-------------|
| `tools.ts` | `DebugInfo` interface + collectors that pull from `src/monitoring/metrics.ts` and `src/health/endpoints.ts`. |

## For AI Agents

### Working In This Directory
- Snapshots are read-only; do not mutate metric counters or cache state from here.

## Dependencies

### Internal
- `src/firewalla/client.ts`, `src/monitoring/logger.ts`, `src/monitoring/metrics.ts`, `src/health/endpoints.ts`, `src/utils/timestamp.ts`.

<!-- MANUAL: -->
