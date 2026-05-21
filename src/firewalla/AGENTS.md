<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# firewalla

## Purpose
The MSP API HTTP client. **Every** outbound call to Firewalla flows through `FirewallaClient` — handlers never use axios directly.

## Key Files

| File | Description |
|------|-------------|
| `client.ts` | `FirewallaClient`: axios with internal response cache (TTL from `CACHE_TTL`), rate limit throttling, box-scoped routing, geographic enrichment hook. Retry policy lives in `src/utils/retry-manager.ts` and is opt-in per call site. |

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
- 429 / 5xx surface as thrown errors with mapped messages (see the response interceptor in `client.ts`); call sites that need retry use `src/utils/retry-manager.ts`.

## Dependencies

### Internal
- `src/config/config.ts`, `src/utils/geographic.ts`, `src/monitoring/logger.ts`.

### External
- `axios`.

<!-- MANUAL: -->
