<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# servers

## Purpose
Deployment manifests for external MCP server registries (Docker MCP Registry, Docker Desktop integration).

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `firewalla-mcp-server/` | Docker MCP Registry server descriptor (see `firewalla-mcp-server/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- These manifests are consumed by external registries; their env-var declarations are **expected vars**, not necessarily ones the runtime currently reads. Verify against `src/config/config.ts` and `src/production/config.ts` before treating them as authoritative.

<!-- MANUAL: -->
