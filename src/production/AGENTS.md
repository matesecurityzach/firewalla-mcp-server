<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# production

## Purpose
Production-deployment variant of the base config. Extends `FirewallaConfig` with operational knobs (log level, CORS, trusted proxies, graceful-shutdown timeout) used when running behind a reverse proxy or in a container fleet.

## Key Files

| File | Description |
|------|-------------|
| `config.ts` | `ProductionConfig` interface + `getProductionConfig()` loader. Honors `MCP_TEST_MODE`. |

## For AI Agents

### Working In This Directory
- The runtime currently consumes `src/config/config.ts`, not this file directly. If you need these production knobs, wire them into the bootstrap in `src/server.ts`.
- Keep this file's env-var contract consistent with the Docker descriptor at `servers/firewalla-mcp-server/server.yaml`.

## Dependencies

### Internal
- `src/utils/env.ts`, `src/types.ts`.

### External
- `dotenv`.

<!-- MANUAL: -->
