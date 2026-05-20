<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# prompts

## Purpose
MCP **prompts** — parameterized templates clients can invoke to produce structured analytical outputs (`security_report`, `threat_analysis`, `bandwidth_analysis`, `device_investigation`, `network_health_check`). Registered via `setupPrompts()` in `server.ts`, which wires both `ListPrompts` and `GetPrompt` handlers.

The actual data-gathering + narrative composition lives in `src/reports/index.ts`. Each prompt case is a thin adapter that calls the corresponding builder and emits its `narrative` string as a user message. For agent-callable equivalents that return the same `{ data, narrative }` payload as a tool result, see `src/tools/handlers/reports.ts` (the `generate_*` tools).

## Key Files

| File | Description |
|------|-------------|
| `index.ts` | Exports `PROMPT_CATALOG` (single source of truth for the prompt list) and `setupPrompts(server, firewalla)` — registers `ListPrompts` + `GetPrompt`. Each `GetPrompt` case delegates to a builder in `src/reports/index.ts`. |

## For AI Agents

### Working In This Directory
- Prompts are **templates**, not tools — they assemble messages the LLM then runs. Data fetching and analytical math live in `src/reports/`.
- When adding a prompt: add an entry to `PROMPT_CATALOG`, add a `case` in `GetPrompt`, and add the matching builder to `src/reports/index.ts`. If the data is also useful as a tool result, add a `generate_*` handler in `src/tools/handlers/reports.ts` so the prompt and tool share one builder.
- Do not duplicate report data-gathering across prompts and tools — both must call the shared builder.

### Testing Requirements
- `tests/prompts/index.test.ts` covers registration. Builder behavior is covered via `tests/tools/handlers/reports.test.ts`.

## Dependencies

### Internal
- `src/reports/index.ts` (builders), `src/firewalla/client.ts` (passed into builders).

### External
- `@modelcontextprotocol/sdk/types`.

<!-- MANUAL: -->
