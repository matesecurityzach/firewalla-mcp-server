<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# prompts

## Purpose
MCP **prompts** — parameterized templates clients can invoke to produce structured analytical outputs (security report, threat analysis, bandwidth analysis, device investigation, network health check). Registered via `setupPrompts()` in `server.ts`.

## Key Files

| File | Description |
|------|-------------|
| `index.ts` | `setupPrompts(server, firewalla)` — declares the prompt list and renders each prompt's messages on `prompts/get`. |

## For AI Agents

### Working In This Directory
- Prompts are templates, not tools — they assemble messages the LLM then runs. Keep them deterministic; data fetching belongs in tools/resources.
- New prompt: add arg schema + name/description in the list handler, render messages in the get handler.

### Testing Requirements
- See `tests/prompts/index.test.ts`.

## Dependencies

### Internal
- `src/firewalla/client.ts` (for templates that inline current data).

### External
- `@modelcontextprotocol/sdk/types`.

<!-- MANUAL: -->
