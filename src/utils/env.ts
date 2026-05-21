/**
 * @fileoverview Environment variable utilities for configuration parsing
 *
 * Provides type-safe utilities for parsing and validating environment variables
 * with appropriate error handling and default values.
 */

import { logger } from '../monitoring/logger.js';

/**
 * Gets a required environment variable or throws an error if not found
 *
 * @param name - The environment variable name
 * @returns The environment variable value
 * @throws {Error} If the environment variable is not set or empty
 */
export function getRequiredEnvVar(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Required environment variable ${name} is not set`);
  }
  return value;
}

/**
 * Gets an optional environment variable with a fallback default value
 *
 * @param name - The environment variable name
 * @param defaultValue - The default value to use if not set
 * @returns The environment variable value or default
 */
export function getOptionalEnvVar(name: string, defaultValue: string): string {
  return process.env[name] || defaultValue;
}

/**
 * Safely parses an environment variable to an integer with validation
 *
 * @param name - The environment variable name to parse
 * @param defaultValue - The default value to use if parsing fails
 * @param min - Optional minimum value for validation
 * @param max - Optional maximum value for validation
 * @returns The parsed integer value or the default value
 * @throws {Error} If the parsed value is outside the valid range
 */
export function getOptionalEnvInt(
  name: string,
  defaultValue: number,
  min?: number,
  max?: number
): number {
  const envValue = process.env[name];
  if (envValue === undefined || envValue === '') {
    return defaultValue;
  }

  const parsed = parseInt(envValue, 10);
  if (!Number.isFinite(parsed)) {
    logger.warn(`Invalid numeric value for environment variable`, {
      environment_variable: name,
      invalid_value: envValue,
      default_value: defaultValue,
      action: 'using_default',
    });
    return defaultValue;
  }

  if (min !== undefined && parsed < min) {
    throw new Error(
      `Environment variable ${name} must be at least ${min}, got: ${parsed}`
    );
  }

  if (max !== undefined && parsed > max) {
    throw new Error(
      `Environment variable ${name} must be at most ${max}, got: ${parsed}`
    );
  }

  return parsed;
}

/**
 * Safely parses an environment variable to a boolean with validation
 *
 * @param name - The environment variable name to parse
 * @param defaultValue - The default value to use if parsing fails
 * @returns The parsed boolean value or default
 */
export function getOptionalEnvBoolean(
  name: string,
  defaultValue: boolean
): boolean {
  const envValue = process.env[name];
  if (envValue === undefined || envValue === '') {
    return defaultValue;
  }

  const normalized = envValue.toLowerCase().trim();
  if (['true', '1', 'yes', 'on'].includes(normalized)) {
    return true;
  }
  if (['false', '0', 'no', 'off'].includes(normalized)) {
    return false;
  }

  logger.warn(`Invalid boolean value for environment variable`, {
    environment_variable: name,
    invalid_value: envValue,
    default_value: defaultValue,
    action: 'using_default',
  });
  return defaultValue;
}

/**
 * Parses a comma-separated env var into a trimmed, non-empty string list.
 */
function parseCsvEnv(name: string, defaultValue: string[]): string[] {
  const raw = process.env[name];
  if (raw === undefined || raw === '') {
    return defaultValue;
  }
  return raw
    .split(',')
    .map(s => s.trim())
    .filter(s => s.length > 0);
}

/**
 * Parses transport configuration from environment variables
 *
 * Extracts shared logic for parsing MCP_TRANSPORT, MCP_HTTP_PORT, MCP_HTTP_PATH,
 * MCP_HTTP_HOST, MCP_HTTP_ALLOWED_HOSTS, MCP_HTTP_ALLOWED_ORIGINS, and
 * MCP_HTTP_BEARER to prevent duplication between config files.
 *
 * The HTTP transport defaults to binding to 127.0.0.1 and only allowing the
 * `localhost`/`127.0.0.1` Host header — this is the safe default. Operators
 * who need to expose the transport more broadly must opt in explicitly via
 * MCP_HTTP_HOST and MCP_HTTP_ALLOWED_HOSTS.
 *
 * @returns Parsed transport configuration object
 * @throws {Error} If transport type is invalid
 */
export function parseTransportConfig(): {
  type: 'stdio' | 'http';
  port: number;
  path: string;
  host: string;
  allowedHosts: string[];
  allowedOrigins: string[];
  bearerToken?: string;
} {
  // Parse and validate transport type
  const transportTypeRaw = getOptionalEnvVar(
    'MCP_TRANSPORT',
    'stdio'
  ).toLowerCase();
  let transportType: 'stdio' | 'http';

  if (transportTypeRaw === 'stdio' || transportTypeRaw === 'http') {
    transportType = transportTypeRaw;
  } else {
    throw new Error(
      `Invalid MCP_TRANSPORT value: ${transportTypeRaw}. Must be 'stdio' or 'http'.`
    );
  }

  // Parse port with validation
  const port = getOptionalEnvInt('MCP_HTTP_PORT', 3000, 1, 65535);

  // Parse and normalize path (ensure leading slash)
  const rawPath = getOptionalEnvVar('MCP_HTTP_PATH', '/mcp');
  const path = rawPath.startsWith('/') ? rawPath : `/${rawPath}`;

  // Default to loopback-only bind — this is the safe default. Node's
  // http.Server.listen(port) without a host binds 0.0.0.0, which would
  // expose the server to every interface on the machine.
  const host = getOptionalEnvVar('MCP_HTTP_HOST', '127.0.0.1');

  // Allowed Host header values for the request-time check. Always include
  // the configured bind host and 'localhost'/'127.0.0.1' so loopback access
  // works out of the box.
  const baseHosts = [host, 'localhost', '127.0.0.1', `localhost:${port}`,
    `127.0.0.1:${port}`, `[::1]:${port}`];
  const allowedHosts = Array.from(
    new Set([
      ...baseHosts,
      ...parseCsvEnv('MCP_HTTP_ALLOWED_HOSTS', []),
    ])
  );

  // Origin allowlist. Empty means: only allow requests with no Origin or
  // an Origin that matches the Host header (same-origin).
  const allowedOrigins = parseCsvEnv('MCP_HTTP_ALLOWED_ORIGINS', []);

  const bearerToken = process.env.MCP_HTTP_BEARER || undefined;

  return {
    type: transportType,
    port,
    path,
    host,
    allowedHosts,
    allowedOrigins,
    bearerToken,
  };
}
