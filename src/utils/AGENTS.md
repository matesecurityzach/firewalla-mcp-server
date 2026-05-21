<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# utils

## Purpose
Cross-cutting helpers used by tools, the client, and validation. Pure functions where possible.

## Key Files

| File | Description |
|------|-------------|
| `env.ts` | `getRequiredEnvVar`, `getOptionalEnvVar`, `getOptionalEnvInt`, `parseTransportConfig`. All env access goes through here. |
| `timestamp.ts` | ISO 8601 + Unix conversions, `getCurrentTimestamp()`, `safeUnixToISOString()`. |
| `geographic.ts` | IP → geo (country, city, ASN) lookup using `geoip-lite`. |
| `geographic-enrichment-pipeline.ts` | Batched enrichment over collections of entities (flows/alarms). |
| `pagination.ts` | Cursor + page-based pagination helpers. |
| `data-normalizer.ts` | Shape-normalizes API responses across entity types. |
| `data-validator.ts` | Lightweight runtime checks on returned API data. |
| `field-normalizer.ts` | Field-name case + alias normalization. |
| `null-safety.ts` | Defensive helpers for sparse responses. |
| `unified-response.ts` | Common success/error envelope for tool outputs. |
| `response-standardizer.ts` | Cross-tool response shape coercion. |
| `query-validator.ts` | Lightweight query-string sanity checks. |
| `simple-boolean-translator.ts` | Faster path for "field:true/false" expressions. |
| `alarm-id-validation.ts` | Strict path-segment validators (alarm/rule/target-list IDs, box GIDs) — whitelist `[a-zA-Z0-9_-]`, length-capped, used at every `/v2/{resource}/{id}` interpolation in `client.ts`. |
| `bulk-operation-manager.ts` | Batching + result aggregation for bulk handlers. |
| `streaming-manager.ts` | Chunked response orchestration. |
| `timeout-manager.ts` | Per-call timeout enforcement. |
| `retry-manager.ts` | Opt-in retry policy (exponential backoff) — the FirewallaClient axios instance itself does not auto-retry, so callers that need retry wrap their request via this helper. |
| `platform.ts` | OS/runtime detection helpers. |
| `simple-utils.ts` | Misc small helpers (object/array). |

## For AI Agents

### Working In This Directory
- Don't reach for `process.env` directly — go through `env.ts`.
- Keep helpers pure and side-effect free; anything stateful belongs in `src/monitoring/` or `src/firewalla/client.ts`.

### Testing Requirements
- One test file per util under `tests/utils/`.

## Dependencies

### External
- `geoip-lite`, `dotenv`.

<!-- MANUAL: -->
