<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# tests

## Purpose
Jest test suites. Layout mirrors `src/` so each module's tests sit at the parallel path under `tests/`.

## Key Files

| File | Description |
|------|-------------|
| `setup.ts` | Lightweight setup harness imported by individual suites. |
| `user-experience-improvements.test.ts` | End-to-end UX behavior assertions across tools. |

## Subdirectories

| Directory | Purpose |
|-----------|---------|
| `setup/` | Jest global setup hooks (see `setup/AGENTS.md`). |
| `config/` | Tests + shared fixtures for `src/config/` (see `config/AGENTS.md`). |
| `integration/` | Cross-module integration tests (see `integration/AGENTS.md`). |
| `monitoring/` | Tests for `src/monitoring/` (see `monitoring/AGENTS.md`). |
| `prompts/` | Tests for `src/prompts/` (see `prompts/AGENTS.md`). |
| `resources/` | Tests for `src/resources/` (see `resources/AGENTS.md`). |
| `search/` | Tests for `src/search/` and boolean translation (see `search/AGENTS.md`). |
| `tools/` | Tests for `src/tools/` setup wiring (see `tools/AGENTS.md`). |
| `utils/` | Tests for `src/utils/` modules (see `utils/AGENTS.md`). |
| `validation/` | Tests for `src/validation/` and field mapping (see `validation/AGENTS.md`). |

## For AI Agents

### Working In This Directory
- Uses `ts-jest/presets/default-esm`. Imports require `.js` extensions; the `moduleNameMapper` in `jest.config.cjs` resolves them.
- `tsconfig.test.json` relaxes unused-locals — don't take that as license in production code.
- `testTimeout: 10000`, `forceExit: true`. If you write a test that hangs, fix the underlying timer/listener leak rather than relying on forceExit.

### Testing Requirements
- Single file: `npm test -- tests/path/file.test.ts`
- Single test name: `npm test -- -t "fragment"`
- Fast loop while developing: `npm run test:quick`

### Common Patterns
- HTTP mocking via `nock`.
- Validators tested directly without spinning up the MCP server.
- Tools tested by constructing the handler class and calling `execute()` with a stubbed client.

## Dependencies

### External
- `jest`, `ts-jest`, `nock`, `@types/jest`.

### Internal
- All of `src/`.

<!-- MANUAL: -->
