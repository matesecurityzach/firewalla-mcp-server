<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# monitoring

## Purpose
Logging and lightweight in-process metrics. Imported throughout the server for structured logs and per-tool counters/timers.

## Key Files

| File | Description |
|------|-------------|
| `logger.ts` | Structured logger (`logger.info` / `.warn` / `.error` / `.debug`). Honors `DEBUG=mcp:*`. Use instead of `console.log`. |
| `metrics.ts` | `metrics.count(name)` + `metrics.timing(name, ms)`. Counters and histograms aggregated in-memory for `src/debug/tools.ts` to expose. |

## For AI Agents

### Working In This Directory
- Production code uses `logger` exclusively; `console.log` is lint-blocked. The one exception is `src/tools/registry.ts:221` (stderr write for forced-registration warnings).
- Metric names should be dotted lowercase: `tool.success`, `tool.error`, `tool.latency_ms`.

### Testing Requirements
- See `tests/monitoring/metrics.test.ts`.

<!-- MANUAL: -->
