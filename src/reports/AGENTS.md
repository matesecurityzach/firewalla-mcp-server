<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# reports

## Purpose
Shared report builders. Each builder gathers data from `FirewallaClient`, computes derived analytical fields (threat patterns, flow patterns, health scores), and returns a `{ data, narrative }` pair. Both `src/prompts/index.ts` (MCP prompts) and `src/tools/handlers/reports.ts` (agent-callable `generate_*` tools) consume these — the same composed context is available as either a chat message or a structured tool result.

## Key Files

| File | Description |
|------|-------------|
| `index.ts` | Exports `buildSecurityReport`, `buildThreatAnalysis`, `buildBandwidthAnalysis`, `buildDeviceInvestigationReport`, `buildNetworkHealthReport`. Internal helpers `analyzeThreatPatterns`, `analyzeFlowPatterns`, `calculateNetworkHealthScore`, `calculatePerformanceScore`, `calculateSecurityScore`. |

## For AI Agents

### Working In This Directory
- Builders are the **single source of truth** for the corresponding prompt and tool. If you change one, both surfaces inherit the change — verify by reading `src/prompts/index.ts` and `src/tools/handlers/reports.ts`.
- The `narrative` field is the markdown-formatted user-message text that the MCP prompt historically returned. Keep it stable — downstream consumers may parse it.
- The `data` field is the structured payload returned (alongside `narrative`) by the `generate_*` tools. Add new analytical fields here, not in the narrative.

### Testing Requirements
- Tests live in `tests/tools/handlers/reports.test.ts` (covers builders via the tool handlers) and `tests/prompts/index.test.ts` (covers prompt wiring). Mock `FirewallaClient` at the boundary.

## Dependencies

### Internal
- `src/firewalla/client.ts` (passed in via each builder), `src/types.ts`, `src/utils/timestamp.ts`.

<!-- MANUAL: -->
