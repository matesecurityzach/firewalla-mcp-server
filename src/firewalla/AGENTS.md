<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# firewalla

## Purpose
The MSP API HTTP client. **Every** outbound call to Firewalla flows through `FirewallaClient` — handlers never use axios directly.

## Key Files

| File | Description |
|------|-------------|
| `client.ts` | `FirewallaClient`: axios + axios-retry, internal response cache (TTL from `CACHE_TTL`), rate limit throttling, box-scoped routing, geographic enrichment hook. |

## For AI Agents

### Working In This Directory
- Adding an endpoint? Verify it against `docs/firewalla-api-reference.md` first. Box-scoped routes only: `/v2/boxes/{box_gid}/{resource}`.
- Cache key must include all parameters that affect the response — collisions return stale data silently.
- Errors should propagate as axios errors; let `src/validation/error-handler.ts` shape them at the tool boundary.

### Testing Requirements
- Mock with `nock` against the MSP base URL (`https://{msp_id}`).
- Don't hit the live API in unit tests; use the scripts under `/scripts` for manual checks.

### Common Patterns
- Methods are organized by resource (flows, alarms, devices, rules, target lists, boxes, stats).
- Retry uses exponential backoff for 429 / 5xx.

## Dependencies

### Internal
- `src/config/config.ts`, `src/utils/geographic.ts`, `src/monitoring/logger.ts`.

### External
- `axios`, `axios-retry`.

<!-- MANUAL: -->
