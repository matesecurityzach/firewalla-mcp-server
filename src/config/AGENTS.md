<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# config

## Purpose
Environment-driven configuration loading, plus typed constants used across the server (limits, response sizing, security knobs, correlation rules).

## Key Files

| File | Description |
|------|-------------|
| `config.ts` | `getConfig()` + exported `config` instance. Loads `FIREWALLA_MSP_TOKEN`, `FIREWALLA_MSP_ID`, transport settings, cache TTL, rate limits, etc. Honors `MCP_TEST_MODE`. |
| `test-mode-config.ts` | Dummy credentials for `MCP_TEST_MODE=true` (Docker health checks). |
| `security.ts` | `SecurityManager` and security-related constants used by `src/health/endpoints.ts`. |
| `limits.ts` | Numeric ceilings for pagination, search, response sizing. |
| `response-config.ts` | Response shaping defaults (truncation thresholds, field-level optimization toggles). |
| `correlation-patterns.ts` | Predefined cross-entity correlation patterns used by enhanced query/search. |

## For AI Agents

### Working In This Directory
- New env var? Add it through `src/utils/env.ts` helpers (`getRequiredEnvVar`, `getOptionalEnvInt`) so validation stays uniform.
- Bounds are enforced on integer env vars (e.g., `CACHE_TTL` clamped 0–3600). Keep bounds documented in `CLAUDE.md` if you change them.

### Common Patterns
- `dotenv.config()` is called once at module load.
- `getConfig()` is called once and exported as a constant; do not call it again at runtime.

## Dependencies

### Internal
- `src/utils/env.ts` for parsing helpers.
- `src/types.ts` for `FirewallaConfig`.

### External
- `dotenv`.

<!-- MANUAL: -->
