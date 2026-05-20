<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# health

## Purpose
Health-check primitives used by Docker and orchestrators to verify the server is alive and the upstream MSP API is reachable.

## Key Files

| File | Description |
|------|-------------|
| `endpoints.ts` | `HealthCheckManager` + `HealthStatus` shape (`healthy` / `degraded` / `unhealthy`). Aggregates per-check results with response times. |

## For AI Agents

### Working In This Directory
- Health checks should be **cheap and timeboxed** — they run frequently.
- A "degraded" verdict is preferable to "unhealthy" for transient upstream issues; reserve `unhealthy` for hard auth/config failures.

## Dependencies

### Internal
- `src/firewalla/client.ts`, `src/config/security.ts`, `src/config/config.ts`, `src/utils/timestamp.ts`.

<!-- MANUAL: -->
