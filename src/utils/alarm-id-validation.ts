/**
 * Path-segment identifier validation for Firewalla MCP Server.
 *
 * These validators gate values that are interpolated into MSP API URL
 * paths (e.g. /v2/alarms/{gid}/{alarmId}, /v2/rules/{ruleId}/pause). The
 * security audit (H-5) found that the previous validateAlarmId rejected
 * only empty/null/undefined and let any other string — including `..`,
 * `/`, `?`, `#`, query-strings, and unicode whitespace — into the URL
 * path. The whitelist below blocks every meaningful smuggling vector.
 *
 * Callers should still use encodeURIComponent() at the path-interpolation
 * site as defense in depth; the validator's job is to reject obvious
 * tampering early so we can produce a clear error.
 */

const ID_WHITELIST = /^[a-zA-Z0-9_-]+$/;
const ID_MAX_LENGTH = 128;

function validatePathSegment(
  id: string | number,
  kindLabel: string
): string {
  const stringId = String(id).trim();

  if (!stringId || stringId.length === 0) {
    throw new Error(`Invalid ${kindLabel}: cannot be empty`);
  }
  if (stringId === '0' || stringId === 'null' || stringId === 'undefined') {
    throw new Error(
      `Invalid ${kindLabel}: "${stringId}" is not a valid ${kindLabel}`
    );
  }
  if (stringId.length > ID_MAX_LENGTH) {
    throw new Error(
      `Invalid ${kindLabel}: exceeds maximum length of ${ID_MAX_LENGTH}`
    );
  }
  if (!ID_WHITELIST.test(stringId)) {
    throw new Error(
      `Invalid ${kindLabel}: must contain only [a-zA-Z0-9_-]`
    );
  }
  return stringId;
}

/**
 * Validates that an alarm ID is acceptable for use in an MSP API path.
 * @param id - The alarm ID to validate
 * @returns The validated alarm ID (trimmed)
 * @throws Error if the ID is invalid
 */
export function validateAlarmId(id: string | number): string {
  return validatePathSegment(id, 'alarm ID');
}

/**
 * Validates a rule ID for use in an MSP API path (e.g. /v2/rules/{id}/pause).
 */
export function validateRuleId(id: string | number): string {
  return validatePathSegment(id, 'rule ID');
}

/**
 * Validates a target-list ID for use in an MSP API path.
 */
export function validateTargetListId(id: string | number): string {
  return validatePathSegment(id, 'target list ID');
}

/**
 * Validates a box GID (UUID-shaped) for use in an MSP API path. Accepts the
 * standard UUID format with or without dashes; rejects anything containing
 * path-traversal or URL-control characters.
 */
export function validateBoxGid(id: string): string {
  const stringId = String(id).trim();
  if (!stringId) {
    throw new Error('Invalid box GID: cannot be empty');
  }
  if (stringId.length > ID_MAX_LENGTH) {
    throw new Error(
      `Invalid box GID: exceeds maximum length of ${ID_MAX_LENGTH}`
    );
  }
  if (!ID_WHITELIST.test(stringId)) {
    throw new Error('Invalid box GID: must contain only [a-zA-Z0-9_-]');
  }
  return stringId;
}

/**
 * Validates alarm ID without throwing (returns null on invalid)
 * @param id - The alarm ID to validate
 * @returns The validated alarm ID or null if invalid
 */
export function validateAlarmIdSafe(id: string | number): string | null {
  try {
    return validateAlarmId(id);
  } catch {
    return null;
  }
}
