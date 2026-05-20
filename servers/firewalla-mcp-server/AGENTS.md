<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# firewalla-mcp-server (deployment descriptor)

## Purpose
Docker MCP Registry descriptor used by Docker Desktop and the Docker MCP catalog to surface this server.

## Key Files

| File | Description |
|------|-------------|
| `server.yaml` | Declares the published image, secrets (`FIREWALLA_MSP_TOKEN`), config parameters (`msp_id`, `box_id`), and a set of env vars. |

## For AI Agents

### Working In This Directory
- Several `MCP_*` env vars in this YAML (`MCP_WAVE0_ENABLED`, `MCP_READ_ONLY_MODE`, `MCP_CACHE_ENABLED`, `MCP_DEBUG_MODE`) are **not read by the runtime** today. They are scaffolding from earlier plans. Removing them would clean up Docker Desktop config UX; adding logic to consume them would require changes in `src/config/config.ts` and `src/production/config.ts`.
- The published image tag in this file must match what `docker-publish.yml` actually pushes.

<!-- MANUAL: -->
