<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# tools/handlers tests

## Purpose
Unit tests for individual handler classes in `src/tools/handlers/`. Each test instantiates the handler directly and passes a mocked `FirewallaClient`, so no MCP server is started.

## Key Files

| File | Description |
|------|-------------|
| `investigation.test.ts` | Coverage for the four investigation composite tools (`investigate_ip`, `investigate_device`, `get_alarm_context`, `get_target_timeline`). Asserts validation errors, correlation correctness, and the timeline ordering / kind-discriminator contract. |
| `reports.test.ts` | Coverage for the five report tools (`generate_*`). Asserts `{ data, narrative }` structure, required-parameter handling, and unknown-device-id errors. |

## For AI Agents

### Working In This Directory
- Use simple object fixtures (`makeFlow`, `makeAlarm`, `makeDevice`) rather than `jest.mock` of the whole client module — tests stay readable.
- Parse the unified-response envelope: `JSON.parse(resp.content[0].text)` returns `{ success, data, meta }`. The structured payload from the handler lives at `.data.data` for `generate_*` tools (which wrap a `{ data, narrative }` object), and directly at `.data` for investigation tools.

### Common Patterns
- Always assert the error path (`isError: true`) for missing required parameters.
- For correlation primitives, use multiple alarm/flow fixtures with overlapping device IDs / IPs so the correlation logic has something to correlate.

## Dependencies

### Internal
- `src/tools/handlers/*` (under test), `src/firewalla/client.ts` (mocked).

<!-- MANUAL: -->
