<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# validation (tests)

## Purpose
Tests for `src/validation/`, plus a regression-prevention catalog of historical input bugs.

## Key Files

| File | Description |
|------|-------------|
| `field-validator.test.ts` | Field-name + value validation per entity type. |
| `geographic-field-mapping.test.ts` | Geo-enrichment field mapping across flows/alarms. |
| `ip-geolocation-enrichment.test.ts` | IP → geo lookups with `geoip-lite` fixtures. |
| `query-syntax.test.ts` | Parser + operator validation across the full query grammar. |
| `regression-prevention.test.ts` | Catalog of historical query/parameter bugs. Append, don't rewrite. |

## For AI Agents

### Working In This Directory
- `regression-prevention.test.ts` is the firewall against re-regressions — every shipped bug fix should add a case here.

<!-- MANUAL: -->
