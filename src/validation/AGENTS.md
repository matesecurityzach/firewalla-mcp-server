<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-05-20 | Updated: 2026-05-20 -->

# validation

## Purpose
The validation, normalization, and error-shaping layer that sits between raw tool input and the API client. Tool handlers should delegate parameter checks here rather than re-implementing them.

## Key Files

| File | Description |
|------|-------------|
| `error-handler.ts` | `ParameterValidator`, `SafeAccess`, `ErrorType`, `createErrorResponse()`. Canonical error envelope construction. |
| `error-classification.ts` | Maps raw errors to `ErrorType` and links to remediation docs. |
| `error-formatter.ts` | Pretty / structured formatting for error responses. |
| `enhanced-query-validator.ts` | High-level query validation including grammar + field availability. |
| `field-validator.ts` | Field-name + value validation per entity type. |
| `field-mapper.ts` | Cross-entity field aliasing + correlation field name resolution (used by search). |
| `enhanced-correlation.ts` | Cross-entity correlation scoring and validation. |
| `operator-validator.ts` | Validates use of operators (`AND`, `OR`, `NOT`, comparisons) for the given field type. |
| `parameter-sanitizer.ts` | Strips/escapes user-supplied parameter values (injection defense). |
| `progressive-validator.ts` | Multi-stage validation reporting (collect errors rather than fail-fast). |
| `cursor-validator.ts` | Validates pagination cursors. |
| `resource-validator.ts` | Validates MCP resource URIs + arguments. |

## For AI Agents

### Working In This Directory
- All error responses must go through `createErrorResponse(name, message, ErrorType, details)` — don't construct raw error JSON in handlers.
- Field availability per entity type lives in `field-mapper.ts`. Adding a new searchable field means updating `FIELD_MAPPINGS` there.

### Testing Requirements
- See `tests/validation/`. Regression suite `regression-prevention.test.ts` covers the catalog of historical input bugs.

### Common Patterns
- Validators return `ValidationResult { valid: boolean; errors?: string[] }` and a normalized value.
- `SafeAccess` for nullable nested lookups instead of `?.?.?.`.

## Dependencies

### Internal
- `src/search/*`, `src/utils/*`.

<!-- MANUAL: -->
