<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# handlers

## Purpose
One file per tool category. Each file exports handler classes that implement `ToolHandler` from `base.ts`. The `ToolRegistry` in `../registry.ts` instantiates them at startup.

## Key Files

| File | Description |
|------|-------------|
| `base.ts` | `ToolHandler` abstract class: `name`, `category`, `execute(args, firewalla)`. All handlers extend this. |
| `security.ts` | `GetActiveAlarmsHandler`, `GetSpecificAlarmHandler`, `DeleteAlarmHandler` (the last is intentionally not registered). |
| `network.ts` | `GetFlowDataHandler` + convenience wrappers `GetBandwidthUsageHandler`, `GetOfflineDevicesHandler`. |
| `device.ts` | `GetDeviceStatusHandler`. |
| `rules.ts` | Full CRUD over rules + target lists: `GetNetworkRulesHandler`, `PauseRuleHandler`, `ResumeRuleHandler`, `GetTargetListsHandler`, `GetSpecificTargetListHandler`, `CreateTargetListHandler`, `UpdateTargetListHandler`, `DeleteTargetListHandler`, `GetNetworkRulesSummaryHandler`. |
| `analytics.ts` | `GetBoxesHandler`, `GetSimpleStatisticsHandler`, `GetStatisticsByRegionHandler`, `GetStatisticsByBoxHandler`, `GetRecentFlowActivityHandler`, `GetFlowInsightsHandler`, `GetAlarmTrendsHandler`, `GetRuleTrendsHandler`. |
| `search.ts` | `SearchFlowsHandler`, `SearchAlarmsHandler`, `SearchRulesHandler`, `SearchDevicesHandler`, `SearchTargetListsHandler` (the last two are client-side filtering wrappers). Handler-level `description` strings are deliberately one-liners; the canonical schemas live in `src/server.ts`. |
| `investigation.ts` | Agent-first correlation primitives: `InvestigateIpHandler`, `InvestigateDeviceHandler`, `GetAlarmContextHandler`, `GetTargetTimelineHandler`. Each fans out to multiple `FirewallaClient` methods and assembles one correlated payload, so agents do not have to chain 4–5 search calls per investigation step. Category: `'investigation'`. |
| `reports.ts` | Agent-callable equivalents of the MCP prompts: `GenerateSecurityReportHandler`, `GenerateThreatAnalysisHandler`, `GenerateBandwidthAnalysisHandler`, `GenerateDeviceInvestigationReportHandler`, `GenerateNetworkHealthReportHandler`. Each returns `{ data, narrative }` via the shared builders in `src/reports/index.ts` (which the MCP prompts also call). Category: `'analytics'`. |
| `bulk-alarms.ts` | Bulk operations over alarms (used by future bulk tools — present but not currently registered). |
| `bulk-rules.ts` | Bulk operations over rules (same — staged, not registered). |

## For AI Agents

### Working In This Directory
- `name` matches the exact MCP tool name — keep it in sync with the schema entry in `src/server.ts`.
- `execute(args, firewalla)` must return the MCP `CallToolResult` shape (`{ content: [...] }`). Use `createErrorResponse` from `src/validation/error-handler.ts` for failures so the envelope is consistent.
- Validation goes first — parameter checks before any HTTP call. Use the validators in `src/validation/`.
- Don't keep state on handler instances; the registry constructs one per process. Treat handlers as effectively stateless.
- `delete_alarm` is intentionally **not** wired up (MSP API returns false success). Do not register it without confirming the upstream bug is fixed.

### Testing Requirements
- Tests usually instantiate the handler class directly: `new GetActiveAlarmsHandler().execute({ limit: 10 }, mockClient)`.

### Common Patterns
- Schema in `server.ts` declares the inputs; the handler trusts those types but still validates.
- For paginated tools, `limit` is **required** (intentionally — see `SPEC.md`).

## Dependencies

### Internal
- `src/firewalla/client.ts` (passed in via `execute`), `src/validation/*`, `src/utils/*`, `src/search/*` (for `Search*Handler`).

<!-- MANUAL: -->
