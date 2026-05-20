<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# docs

## Purpose
Reference documentation. `firewalla-api-reference.md` is the **authoritative MSP API specification** for this project — every API change must be verified against it.

## Key Files

| File | Description |
|------|-------------|
| `firewalla-api-reference.md` | **Authoritative** Firewalla MSP API v2 spec: endpoints, data models, query syntax, examples. |
| `query-syntax-guide.md` | Full grammar for search queries (`AND`/`OR`/`NOT`, ranges, wildcards). |
| `advanced-query-syntax-examples.md` | Worked examples for complex searches. |
| `field-mappings.md` | Field aliases across entity types (flows / alarms / rules / devices). |
| `error-handling-guide.md` | Error categorization, recovery strategies, response shapes. |
| `geographic-data-handling-guide.md` | IP geolocation enrichment behavior and limitations. |
| `pagination-guide.md` | Cursor / page-based pagination patterns. |
| `rate-limiting-guide.md` | MSP rate limits and client throttling. |
| `limits-and-performance-guide.md` | Tool limits, response sizing, performance targets. |
| `security-policy-guide.md` | Credential handling and operational security guidance. |
| `tool-descriptions-enhancement-guide.md` | Style guide for MCP tool descriptions. |
| `troubleshooting-guide.md` | Operator-side problem catalog. |
| `ollama-mcpo-setup.md` | Setup with Ollama + mcpo orchestrator. |
| `api-documentation-audit-report.md` | Historical audit of API claim vs reality. |
| `data-audit-report.md` | Historical audit of returned data shapes. |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `clients/` | Per-client setup guides (Claude Desktop, Claude Code, VS Code, Cursor, Cline, Roocode) (see `clients/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- When changing an endpoint, parameter, or query operator in source, update the matching section here in the same PR.
- `firewalla-api-reference.md` claims override `SPEC.md` if they conflict.

### Common Patterns
- Markdown with code-fenced JSON/HTTP/TypeScript examples.
- Frontmatter not used; section anchors are the linking surface.

## Dependencies

### Internal
- Cited from `CLAUDE.md`, `README.md`, error messages in `src/validation/error-classification.ts`.

<!-- MANUAL: -->
