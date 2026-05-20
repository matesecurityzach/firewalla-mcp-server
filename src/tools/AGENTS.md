<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# tools

## Purpose
MCP tool dispatch layer. `setupTools()` registers a single `CallToolRequestSchema` handler that resolves tool names against `ToolRegistry` and invokes the matching handler class.

## Key Files

| File | Description |
|------|-------------|
| `index.ts` | `setupTools(server, firewalla)` — wires the dispatcher, error path, and telemetry counters. Current registered count is 37 (23 direct API + 5 wrappers + 4 investigation composite + 5 report composite). |
| `registry.ts` | `ToolRegistry`: instantiates and registers every handler class. **Source of truth for which tools are live.** `DeleteAlarmHandler` is commented out (MSP API false-success bug). |
| `search.ts` | Shared search-tool implementation used by the `Search*Handler` classes. Glues the parser, filter engine, validators, and field mapper. |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `handlers/` | One file per category, each exporting handler classes (see `handlers/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- New tool checklist: (1) add handler class in `handlers/<category>.ts`, (2) `register()` it in `registry.ts`, (3) add the input schema entry to `src/server.ts`'s `ListToolsRequestSchema` block.
- `forceRegister()` exists for testing — don't call it from production code paths.
- The dispatcher emits `tool.success` / `tool.error` / `tool.latency_ms` via `src/monitoring/metrics.ts`. Don't double-count from inside a handler.

### Testing Requirements
- Mirror the structure: tool tests live under `tests/tools/`.
- Construct the handler class directly and call `.execute()` with a mocked `FirewallaClient` — no need to start the MCP server.

### Common Patterns
- Handlers extend `handlers/base.ts` and expose `name`, `category`, and `execute(args, firewalla)`.
- Errors come back via `createErrorResponse` from `src/validation/error-handler.ts`.

## Dependencies

### Internal
- `src/firewalla/client.ts`, `src/validation/*`, `src/monitoring/*`, `src/search/*`, `src/utils/timestamp.ts`.

### External
- `@modelcontextprotocol/sdk/types`.

<!-- MANUAL: -->
