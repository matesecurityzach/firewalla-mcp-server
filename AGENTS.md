<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# firewalla-mcp-server

## Purpose
Model Context Protocol (MCP) server exposing the Firewalla MSP API v2 to LLM clients (Claude Desktop, Claude Code, VS Code, Cursor, Cline, Roocode) through a registry of 37 specialized tools, including 4 correlation primitives and 5 composite report tools designed for downstream AI security-investigation agents. Supports both stdio and Streamable HTTP transports.

## Key Files

| File | Description |
|------|-------------|
| `CLAUDE.md` | Project-level guidance for Claude Code agents (must read first). |
| `SPEC.md` | Protocol-level specification: MCP tools, resources, prompts, error contracts. |
| `README.md` | End-user setup and client integration guide. |
| `USAGE.md` | Practical query examples for end users. |
| `TROUBLESHOOTING.md` | End-user diagnostic playbook. |
| `CHANGELOG.md` | Version history. Current: 1.2.1. |
| `Dockerfile` | Multi-stage container build (Node 18 base). |
| `package.json` | Scripts, deps, bin entry (`dist/server.js`). |
| `tsconfig.json` | Strict ES2020 ESM build config. |
| `tsconfig.test.json` | Test-mode tsconfig (relaxes unused-locals). |
| `jest.config.cjs` | Jest ESM preset, ts-jest, `forceExit: true`. |
| `jest.config.regression.js` | Regression suite config (suite files not present in tree). |
| `eslint.config.js` | Flat-config ESLint for TypeScript. |
| `.prettierrc` / `.prettierignore` | Format rules. |
| `.env.example` | Required + optional env vars. |
| `.mcp.json.example` | Sample MCP client config. |
| `setup-hooks.sh` | Installs git hooks from `.githooks/`. |
| `test-stdio.js` | Quick stdio handshake check. |
| `test-mcp-server.sh` / `diagnose-mcpo.sh` | Manual smoke/diagnostic scripts. |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `src/` | TypeScript source (see `src/AGENTS.md`). |
| `tests/` | Jest tests organized by source-tree mirror (see `tests/AGENTS.md`). |
| `docs/` | API reference and operator guides (see `docs/AGENTS.md`). |
| `scripts/` | One-off shell + node helper scripts (see `scripts/AGENTS.md`). |
| `servers/` | Docker MCP Registry deployment metadata (see `servers/AGENTS.md`). |
| `.github/` | CI/CD workflows (see `.github/AGENTS.md`). |
| `.githooks/` | Local git hooks (see `.githooks/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- **Before any API change**, read `docs/firewalla-api-reference.md` — it is the single source of truth.
- Only invent code paths that match the registry pattern documented in `CLAUDE.md`. There is no `TOOL_SCHEMAS` constant; tool schemas live inline in `src/server.ts`.
- 37 tools are live (23 direct API + 5 convenience wrappers + 4 investigation composite + 5 report composite). `delete_alarm` is intentionally disabled in `src/tools/registry.ts`.
- For agent-facing investigation flows, see `docs/agent-investigation-guide.md` and the `firewalla://reference/*` MCP resources.
- Don't add `console.log`. Use `src/monitoring/logger.ts` or stderr writes for the lint-exempt path.

### Testing Requirements
- `npm run ci:quick` is the minimum gate: format → typecheck → lint → build → fast tests.
- `npm test -- <path>` for a single file; `npm test -- -t "<name>"` for a single test.
- `tests/regression/` is referenced by package scripts but **does not exist** in the working tree.

### Common Patterns
- ESM with `.js` import extensions resolved by `moduleResolution: node` + Jest's `moduleNameMapper`.
- Strict TS (`strict: true`, `noUnusedLocals`, etc.). Test config relaxes these.
- All HTTP calls flow through `src/firewalla/client.ts` — never axios from a handler.

## Dependencies

### External
- `@modelcontextprotocol/sdk` — MCP server runtime + transports.
- `axios` + `axios-retry` — HTTP with exponential backoff.
- `zod` — schema validation (used selectively).
- `geoip-lite` — IP → country/city enrichment.
- `dotenv` — env loading.

<!-- MANUAL: Project-specific notes added below are preserved on regeneration -->
