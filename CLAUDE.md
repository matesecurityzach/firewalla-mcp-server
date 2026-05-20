# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## CRITICAL: Before Any API Development

**READ FIRST**: `docs/firewalla-api-reference.md` — the verified Firewalla MSP API v2 specification. It is the single source of truth for endpoints, data models, and query syntax.

**Hard rules**:
- Only call endpoints documented in `docs/firewalla-api-reference.md`.
- Always use box-scoped routes: `/v2/boxes/{box_gid}/{resource}`.
- Never invent endpoints. Patterns like `/stats/simple`, `/trends/flows`, `/stats/topDevicesByBandwidth` do not exist on the MSP API and must not be added.
- For bandwidth/trends, query `/flows` or `/alarms` with `groupBy` / `sortBy` and aggregate client-side.

## Primary Audience

The downstream consumer of this server is an **AI security-investigation agent**, not a human operator. Several design choices follow from that:

- Tool descriptions in `src/server.ts` must use the **verified Firewalla MSP qualifier names** (`box.id`, `device.id`, `remote.region`, `transfer.total`, etc.) — not invented fields like `gid:` or `bytes:`. The agent grounds queries on whatever the description says; if the description lies, queries silently return empty results.
- Investigation composite tools (`investigate_ip`, `investigate_device`, `get_alarm_context`, `get_target_timeline`) exist because chaining 4–5 `search_*` calls per question is unreliable for agents. Reach for these first; only fall back to direct searches when correlation isn't enough.
- Reference resources at `firewalla://reference/*` are the agent's ground truth (alarm-types, categories, query-syntax). Update them in lockstep with `docs/firewalla-api-reference.md`.
- The agent-facing playbook is `docs/agent-investigation-guide.md`. Read it after the API reference whenever you change the tool surface.

## Architecture

### Tool Registry Pattern (the real shape)
- `src/server.ts` — MCP server bootstrap. Declares the tool schemas in the `ListToolsRequestSchema` response and wires stdio + Streamable HTTP transports. **Schemas live inline here**, not in a `TOOL_SCHEMAS` constant.
- `src/tools/index.ts` — `setupTools()` registers a single `CallToolRequestSchema` handler that delegates execution to the registry.
- `src/tools/registry.ts` — `ToolRegistry` instantiates all handler classes in its constructor. Adding a tool means: (1) add a handler class, (2) register it here, (3) add its schema to the `ListToolsRequestSchema` block in `server.ts`.
- `src/tools/handlers/*.ts` — one file per category (`security`, `network`, `device`, `rules`, `analytics`, `search`, `investigation`, `reports`). Each handler extends the base in `handlers/base.ts` and exposes `name`, `category`, and `execute(args, firewalla)`.
- `src/firewalla/client.ts` — the single HTTP client wrapper around the MSP API (axios + axios-retry, with internal caching).
- `src/reports/index.ts` — shared report builders consumed by both `src/prompts/` and the `generate_*` tools in `src/tools/handlers/reports.ts`.

### What's actually registered (37 active tools)

`DeleteAlarmHandler` exists in `handlers/security.ts` but is intentionally commented out in `registry.ts` because the MSP API returns `{success: true}` without actually deleting. So the imported handler count is 38, but **37 are live**.

- **Security (2)**: `get_active_alarms`, `get_specific_alarm` *(delete_alarm disabled — see comment in `registry.ts`)*
- **Network (1 direct + 2 wrappers)**: `get_flow_data`; wrappers `get_bandwidth_usage`, `get_offline_devices`
- **Device (1)**: `get_device_status`
- **Rules (8 direct + 1 wrapper)**: `get_network_rules`, `pause_rule`, `resume_rule`, `get_target_lists`, `get_specific_target_list`, `create_target_list`, `update_target_list`, `delete_target_list`; wrapper `get_network_rules_summary`
- **Search (3 direct + 2 wrappers)**: `search_flows`, `search_alarms`, `search_rules`; wrappers `search_devices`, `search_target_lists` (client-side filtering)
- **Analytics (8)**: `get_boxes`, `get_simple_statistics`, `get_statistics_by_region`, `get_statistics_by_box`, `get_recent_flow_activity`, `get_flow_insights`, `get_alarm_trends`, `get_rule_trends`
- **Investigation composite (4)**: `investigate_ip`, `investigate_device`, `get_alarm_context`, `get_target_timeline` — fan out to multiple existing client calls and return correlated `{data, narrative?}` payloads. Designed for AI agents that would otherwise chain 4–5 calls per investigation step.
- **Report composite (5)**: `generate_security_report`, `generate_threat_analysis`, `generate_bandwidth_analysis_report`, `generate_device_investigation_report`, `generate_network_health_report` — agent-callable equivalents of the MCP prompts. Each returns `{ data, narrative }` and reuses the builders in `src/reports/`.

If you change which tools exist, also update the schema block in `server.ts`, the registry, the README "Quick Reference," and the JSDoc counts in `registry.ts` / `tools/index.ts` / `server.ts`.

### Resources and prompts
- `src/resources/` — MCP resources. Live data URIs: `firewalla://summary`, `firewalla://devices`, `firewalla://metrics/security`, `firewalla://topology`, `firewalla://threats/recent`, `firewalla://boxes`. Reference URIs: `firewalla://reference/alarm-types`, `firewalla://reference/categories`, `firewalla://reference/query-syntax`. Registered via `setupResources()` in `server.ts` with both `ListResources` and `ReadResource` handlers.
- `src/prompts/` — MCP prompt templates. Registered via `setupPrompts()` with both `ListPrompts` and `GetPrompt` handlers. The actual report-building logic lives in `src/reports/`; the prompt handlers are thin wrappers that emit the `narrative` field as a user message.
- `docs/agent-investigation-guide.md` — the agent-facing investigation playbook (which tool for which question, verified query grammar, pagination/error patterns). Update it when the tool surface changes.

### Validation layer
`src/validation/` contains the parameter validators, query parser, field mapper, and error formatter. The expected error shape across tools is:

```ts
interface StandardError {
  error: true;
  message: string;
  tool: string;
  details?: unknown;
  validation_errors?: string[];
}
```

`createErrorResponse(name, message, ErrorType, details)` from `validation/error-handler.ts` is the canonical way to fail a tool.

### Search subsystem

`src/search/` hosts the **local** query parser and filter engine that powers `search_flows`, `search_alarms`, `search_rules`. The local grammar is permissive (`AND`/`OR`/`NOT`, parentheses, ranges, comparisons, wildcards). What actually reaches the MSP API depends on the route:

- Search tools (`search_*`) translate locally then forward to `firewalla.getFlowData` / `getActiveAlarms` / etc., which pass the resulting query string straight to `/v2/{resource}`.
- Direct tools (`get_active_alarms`, `get_flow_data`, `get_network_rules`) pass the user-supplied `query` argument **straight through** with no translation — only verified MSP qualifiers will match server-side.

Tool descriptions in `src/server.ts` document the **verified MSP qualifier set** for both paths. The local parser will accept richer syntax (e.g. `severity:high` on alarms, computed locally) — but document only the verified set so the agent doesn't build queries that silently fail.

See `firewalla://reference/query-syntax` (resource) and `docs/query-syntax-guide.md` for the full local grammar; `docs/firewalla-api-reference.md` for the verified MSP qualifier tables.

### Transports
The server speaks both stdio (default — for Claude Desktop / Claude Code) and Streamable HTTP (for Docker / orchestrators). Selection happens via `MCP_TRANSPORT` and is parsed in `src/utils/env.ts → parseTransportConfig()`.

## Configuration

Required:
- `FIREWALLA_MSP_TOKEN` — MSP API access token
- `FIREWALLA_MSP_ID` — MSP domain (e.g., `yourdomain.firewalla.net`)

Optional (see `src/config/config.ts` for the full list and bounds):
- `FIREWALLA_BOX_ID` — restrict all calls to a single box GID. If unset, calls span all accessible boxes.
- `FIREWALLA_DEFAULT_BOX_ID` — fallback box for convenience wrappers
- `API_TIMEOUT` (ms, 1000–300000, default 30000)
- `API_RATE_LIMIT` (req/min, 1–1000, default 100)
- `CACHE_TTL` (s, 0–3600, default 300)
- `DEFAULT_PAGE_SIZE` (default 100), `MAX_PAGE_SIZE` (default 10000)
- `MCP_TRANSPORT` (`stdio` | `http`, default `stdio`)
- `MCP_HTTP_PORT` (default 3000), `MCP_HTTP_PATH` (default `/mcp`)
- `MCP_TEST_MODE=true` — start with dummy credentials (for Docker health checks)
- `MCP_DISABLED_TOOLS` — referenced in error messages; **not currently wired into tool dispatch**. Do not rely on it without adding the check.

## Common Commands

### Build / run
```bash
npm install
npm run build              # tsc — runs prebuild → clean first
npm run build:clean        # rimraf dist && build
npm run dev                # build + node dist/server.js
npm run mcp:start          # build + start (stdio by default)
npm run mcp:debug          # DEBUG=mcp:* + build + start
```

### Test
```bash
npm test                            # full jest suite (NODE_ENV=test)
npm run test:watch
npm run test:ci                     # coverage, CI flag set
npm run test:quick                  # fast subset: utils + validation, narrow worker pool
npm run test:unit                   # --testPathPatterns=unit
npm run test:integration            # --testPathPatterns=integration

# Single file
npm test -- tests/path/to/file.test.ts

# Single test name
npm test -- -t "name fragment"

# Just the new agent-first surface
npm test -- tests/tools/handlers/investigation.test.ts tests/tools/handlers/reports.test.ts tests/tools/registry-schema-parity.test.ts
```

> Note: `package.json` defines `test:regression*` scripts, but `tests/regression/` does not exist in the working tree. Those scripts will pass-with-no-tests today. Don't add `--passWithNoTests`-less invocations until that suite is restored.

### Lint / format / types
```bash
npm run lint               # eslint src/**/*.ts
npm run lint:fix
npm run lint:check         # zero warnings allowed (CI gate)
npm run format             # prettier write
npm run format:check
npm run typecheck          # tsc --noEmit
```

### CI gates
```bash
npm run ci:quick           # format:check + typecheck + lint + build + test:quick
npm run ci:full            # ci:quick + test:ci
```

## Adding a Tool — Checklist

1. Add a handler class in the appropriate `src/tools/handlers/<category>.ts`, extending the base in `handlers/base.ts`. Implement `execute(args, firewalla)` and set `name` + `category`.
   - **1a.** If the handler's `category` is a new value, update **both** the `ToolHandler` interface union and the `BaseToolHandler.category` abstract union in `src/tools/handlers/base.ts`. The TypeScript compiler will only flag the mismatch when a concrete handler tries to use the new category.
2. Register the handler in `src/tools/registry.ts → registerHandlers()`.
3. Add the input schema entry to the `tools: [...]` array in `src/server.ts` under `ListToolsRequestSchema`.
4. Wire any new API call through `src/firewalla/client.ts` — never call axios directly from a handler.
5. Validate inputs via `src/validation/` helpers; return errors with `createErrorResponse`.
6. Add tests under `tests/tools/` (unit) and/or `tests/integration/` (against mocked or recorded responses via `nock`).
7. Verify endpoint + parameter names against `docs/firewalla-api-reference.md` before writing the client call.
8. Run `npm test -- tests/tools/registry-schema-parity.test.ts` — it enforces that every registered handler has a matching `ListTools` schema and the active tool count matches the expected value. Update the expected count there too.

## Caching and Rate Limiting

- `FirewallaClient` caches responses with TTL set by `CACHE_TTL` (default 300s). LRU-style eviction; geographic enrichment uses its own longer-lived cache.
- `axios-retry` handles transient failures with exponential backoff.
- Respect the documented MSP limit (~100 req/min, see `SPEC.md`). The client throttles internally but unbounded fan-out from search aggregations can still trip it.

## Known Behaviors / Gotchas

- **`delete_alarm` is disabled** — see `registry.ts:135`. The MSP API returns `{success: true}` but the alarm persists. Do not re-enable without confirming with upstream.
- **Empty `category` field on flows** is normal — Firewalla only classifies recognized domains/services.
- **`get_recent_flow_activity`** caps at ~150 flows to stay within MCP token limits; use `search_flows` with time filters for larger ranges.
- **`get_flow_insights`** uses API-side `groupBy` to handle high-volume networks (300k+ flows/day) without paginating — prefer it over `search_flows` for "did device X visit category Y?" questions.
- **Box ID is optional**: if unset, calls return data across all accessible boxes via the MSP-level routes.

## Debugging

```bash
DEBUG=mcp:* npm run mcp:start        # the wired-up namespace
```

Other DEBUG namespaces referenced in docs (`firewalla:*`, `cache`, `performance`, etc.) are aspirational — verify in `src/monitoring/logger.ts` before depending on them.

## Reference Documentation (in repo)

- `docs/firewalla-api-reference.md` — **authoritative MSP API spec**. Always consult before changing API code.
- `docs/query-syntax-guide.md` — search grammar
- `docs/field-mappings.md` — field aliases across entity types
- `docs/error-handling-guide.md` — error categorization and recovery
- `docs/geographic-data-handling-guide.md` — geo enrichment behavior
- `docs/pagination-guide.md`, `docs/rate-limiting-guide.md`, `docs/limits-and-performance-guide.md`
- `SPEC.md` — protocol-level specification
- `USAGE.md`, `TROUBLESHOOTING.md` — end-user docs

## Project Conventions

- TypeScript strict mode with ES2020 target, ESM (`"type": "module"`). Imports use `.js` extensions (resolved by `moduleResolution: node` + Jest's `moduleNameMapper`).
- Node 18+ required.
- No `console.log` in production code paths — use `src/monitoring/logger.ts`. Stderr writes (e.g., `registry.ts:221`) bypass the lint rule deliberately.
- Tests use ts-jest ESM preset; `tsconfig.test.json` relaxes `noUnusedLocals` and strict initialization for fixtures.

## Commit conventions

- Conventional Commits style (`feat:`, `fix:`, `chore:`, `refactor:`, `docs:`, `style:`, `security:`).
- Commits are GPG-signed and signed-off (`git commit -s`). The `commit.gpgsign` setting is required in the local git config.
- Detailed bodies preferred over one-line subjects when the change spans multiple concerns; see commits `2a750a9` and `e2876d6` for the established shape.
- No `Co-Authored-By` lines for AI tools. Don't add them.
