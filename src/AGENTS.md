<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# src

## Purpose
TypeScript source for the Firewalla MCP server. Entry point is `server.ts`, which wires the `@modelcontextprotocol/sdk` server, both transports (stdio + Streamable HTTP), the tool registry, resources, and prompts.

## Key Files

| File | Description |
|------|-------------|
| `server.ts` | MCP server bootstrap. Declares tool schemas inline in `ListToolsRequestSchema`. Handles stdio + HTTP transport selection and lifecycle. |
| `types.ts` | Shared TypeScript interfaces: `Alarm`, `Flow`, `Device`, `FirewallaConfig`, `SearchParams`, etc. |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `config/` | Env-driven configuration loading (see `config/AGENTS.md`). |
| `firewalla/` | MSP API HTTP client (see `firewalla/AGENTS.md`). |
| `tools/` | MCP tool handlers + registry (see `tools/AGENTS.md`). |
| `resources/` | MCP resource implementations (see `resources/AGENTS.md`). |
| `prompts/` | MCP prompt templates (see `prompts/AGENTS.md`). |
| `reports/` | Shared report builders consumed by both prompts and the `generate_*` tools (see `reports/AGENTS.md`). |
| `search/` | Query parser, filter engine, boolean translator (see `search/AGENTS.md`). |
| `validation/` | Parameter validators, error handling, field mapping (see `validation/AGENTS.md`). |
| `utils/` | Shared utilities: env, timestamps, pagination, geo, etc. (see `utils/AGENTS.md`). |
| `monitoring/` | Logger + metrics primitives (see `monitoring/AGENTS.md`). |
| `health/` | Health check manager (see `health/AGENTS.md`). |
| `debug/` | Runtime debug info aggregator (see `debug/AGENTS.md`). |
| `optimization/` | Response truncation + token budgeting (see `optimization/AGENTS.md`). |
| `production/` | Production-config variant with extra deployment knobs (see `production/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- New tool? See the checklist in `CLAUDE.md` — handler class in `tools/handlers/`, register in `tools/registry.ts`, schema in `server.ts`.
- Strict TS: `noImplicitAny`, `strictNullChecks`, `noUnusedLocals`, `noUnusedParameters` are all on. Keep imports tight.
- ESM-only: every relative import must end in `.js` (resolved by the Jest mapper at test time).

### Testing Requirements
- Tests mirror this tree under `tests/` (e.g., `src/utils/foo.ts` → `tests/utils/foo.test.ts`).

### Common Patterns
- `FirewallaClient` is constructed once at bootstrap and passed by reference into handlers.
- Cross-cutting validation lives in `validation/` — handlers should never re-implement parameter checks.

## Dependencies

### External
- `@modelcontextprotocol/sdk` — server, stdio/HTTP transports, request schemas.
- `axios`.
- `zod`, `dotenv`, `geoip-lite`.

<!-- MANUAL: -->
