<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# resources

## Purpose
MCP **resources** — read-only URIs that expose Firewalla state as named documents (`firewalla://summary`, `firewalla://devices`, etc.). Registered via `setupResources()` in `server.ts`, which now registers both `ListResources` and `ReadResource` handlers so agents can discover the URI set.

Live URIs: `firewalla://summary`, `firewalla://devices`, `firewalla://metrics/security`, `firewalla://topology`, `firewalla://threats/recent`, `firewalla://boxes`.
Reference URIs (verified against `docs/firewalla-api-reference.md`): `firewalla://reference/alarm-types`, `firewalla://reference/categories`, `firewalla://reference/query-syntax`.

## Key Files

| File | Description |
|------|-------------|
| `index.ts` | `setupResources(server, firewalla)` — registers `ListResources` + `ReadResource` handlers and routes URIs to fetchers. Exports `RESOURCE_CATALOG` (the single source of truth for discoverable URIs). |
| `reference.ts` | Static reference data exposed via the `firewalla://reference/*` URIs: `ALARM_TYPES` (1–16), `CONTENT_CATEGORIES`, `QUERY_QUALIFIERS`, `QUERY_SYNTAX`. Updated whenever a verified MSP qualifier set changes. |

## For AI Agents

### Working In This Directory
- Resources are GET-style and should be cheap. If a resource needs heavy aggregation, fan out through the cached `FirewallaClient` calls rather than reimplementing.
- New resource: declare URI, MIME type, and description in the resource list handler; implement the fetcher and route the URI in the read handler.

### Testing Requirements
- See `tests/resources/index.test.ts`.

## Dependencies

### Internal
- `src/firewalla/client.ts`.

### External
- `@modelcontextprotocol/sdk/types`.

<!-- MANUAL: -->
