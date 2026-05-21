import { createHash } from 'node:crypto';
import { productionConfig } from '../production/config.js';
import { getCurrentTimestamp } from '../utils/timestamp.js';

/**
 * Keys that match any of these (case-insensitive substring) are redacted
 * regardless of nesting depth. The list deliberately covers HTTP-header names
 * (authorization, cookie, x-api-key) plus the obvious credential
 * synonyms — the previous implementation matched only "token/password/secret/
 * key", which let the literal axios `Authorization` header through.
 */
const SENSITIVE_KEY_PARTS = [
  'authorization',
  'auth',
  'bearer',
  'cookie',
  'set-cookie',
  'token',
  'password',
  'passwd',
  'secret',
  'api-key',
  'apikey',
  'x-api-key',
  'x-auth-token',
  'credential',
  'private',
];

/**
 * Value-level patterns. Strings that look like a Bearer / Token credential
 * are masked even when they appear under a non-sensitive key (e.g., embedded
 * inside an error message).
 */
const SENSITIVE_VALUE_PATTERNS: RegExp[] = [
  /Token\s+[A-Za-z0-9_\-.]{8,}/gi,
  /Bearer\s+[A-Za-z0-9_\-.]{8,}/gi,
];

const REDACTION_MAX_DEPTH = 6;

// DEBUG environment variable support
const DEBUG_ENABLED =
  process.env.DEBUG === 'firewalla:*' ||
  process.env.DEBUG === '1' ||
  process.env.DEBUG === 'true';
const DEBUG_FILTERS = (process.env.DEBUG || '').split(',').map(f => f.trim());

/**
 * Determines if debug logging is enabled for a given namespace based on environment variable filters.
 *
 * Returns true if global debug is enabled or if the namespace matches any filter (with wildcard support) specified in the `DEBUG` environment variable.
 *
 * @param namespace - The debug namespace to check
 * @returns True if debug logging is enabled for the specified namespace
 */
function shouldDebug(namespace: string): boolean {
  if (!DEBUG_ENABLED && DEBUG_FILTERS.length === 0) {
    return false;
  }
  if (DEBUG_ENABLED) {
    return true;
  }
  return DEBUG_FILTERS.some(filter => {
    if (filter === '*') {
      return true;
    }
    if (filter.endsWith('*')) {
      return namespace.startsWith(filter.slice(0, -1));
    }
    return namespace === filter;
  });
}

export interface LogEntry {
  timestamp: string;
  level: 'error' | 'warn' | 'info' | 'debug';
  message: string;
  service: string;
  version: string;
  metadata?: Record<string, unknown>;
  error?: {
    name: string;
    message: string;
    stack?: string;
  };
  traceId?: string;
  requestId?: string;
}

export class StructuredLogger {
  private service = 'firewalla-mcp-server';
  private version = '1.2.1';
  private logLevel: LogEntry['level'];

  constructor(logLevel?: LogEntry['level']) {
    // Override log level if DEBUG is enabled
    if (DEBUG_ENABLED) {
      this.logLevel = 'debug';
    } else {
      this.logLevel = logLevel || productionConfig.logLevel || 'info';
    }
  }

  private shouldLog(level: LogEntry['level']): boolean {
    const levels = ['error', 'warn', 'info', 'debug'];
    const currentLevelIndex = levels.indexOf(this.logLevel);
    const messageLevelIndex = levels.indexOf(level);
    return messageLevelIndex <= currentLevelIndex;
  }

  private createLogEntry(
    level: LogEntry['level'],
    message: string,
    metadata?: Record<string, unknown>,
    error?: Error,
    traceId?: string,
    requestId?: string
  ): LogEntry {
    const entry: LogEntry = {
      timestamp: getCurrentTimestamp(),
      level,
      message,
      service: this.service,
      version: this.version,
    };

    if (metadata) {
      entry.metadata = this.sanitizeMetadata(metadata);
    }

    if (error) {
      entry.error = {
        name: error.name,
        message: error.message,
        ...(error.stack && { stack: error.stack }),
      };
    }

    if (traceId) {
      entry.traceId = traceId;
    }

    if (requestId) {
      entry.requestId = requestId;
    }

    return entry;
  }

  /**
   * Recursive metadata sanitizer.
   *
   * Walks the metadata object up to REDACTION_MAX_DEPTH levels deep,
   * redacting:
   *   - Any value under a key whose name matches SENSITIVE_KEY_PARTS
   *     (case-insensitive substring match — catches "Authorization",
   *     "authorization", "X-Api-Key", "set-cookie", etc.)
   *   - Any string value matching SENSITIVE_VALUE_PATTERNS, even under a
   *     non-sensitive key (catches Authorization headers that leaked into
   *     error messages, etc.)
   *
   * Cycles are detected via a WeakSet so the walker can't be sent into a
   * loop by a self-referential object. Long sensitive strings are
   * hash-redacted (sha256-prefix) so two log lines mentioning the same
   * credential are correlatable without leaking content.
   */
  private sanitizeMetadata(
    metadata: Record<string, unknown>
  ): Record<string, unknown> {
    const seen = new WeakSet<object>();
    return this.deepRedact(metadata, '', 0, seen) as Record<string, unknown>;
  }

  private deepRedact(
    input: unknown,
    keyName: string,
    depth: number,
    seen: WeakSet<object>
  ): unknown {
    if (depth > REDACTION_MAX_DEPTH) {
      return '[truncated:max-depth]';
    }

    // Redact whole value if key is sensitive (catches { Authorization: …, … })
    if (keyName && this.isSensitiveKey(keyName)) {
      return this.redactValue(input);
    }

    if (input === null || input === undefined) {
      return input;
    }

    if (typeof input === 'string') {
      return this.scrubStringValue(input);
    }

    if (
      typeof input === 'number' ||
      typeof input === 'boolean' ||
      typeof input === 'bigint'
    ) {
      return input;
    }

    if (Array.isArray(input)) {
      if (seen.has(input)) {return '[cycle]';}
      seen.add(input);
      return input.map(el => this.deepRedact(el, '', depth + 1, seen));
    }

    if (typeof input === 'object') {
      const obj = input as Record<string, unknown>;
      if (seen.has(obj)) {return '[cycle]';}
      seen.add(obj);
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(obj)) {
        out[k] = this.deepRedact(v, k, depth + 1, seen);
      }
      return out;
    }

    // functions, symbols — best-effort stringify
    return String(input);
  }

  private isSensitiveKey(name: string): boolean {
    const lower = name.toLowerCase();
    return SENSITIVE_KEY_PARTS.some(part => lower.includes(part));
  }

  /**
   * Mask a value that lives under a sensitive key. Short values are fully
   * starred; longer ones become a SHA256 prefix so distinct credentials are
   * still distinguishable in logs without leaking content.
   */
  private redactValue(value: unknown): string {
    if (value === null || value === undefined) {return '[redacted]';}
    const str = typeof value === 'string' ? value : JSON.stringify(value);
    if (str.length <= 8) {return '*'.repeat(Math.max(1, str.length));}
    const digest = createHash('sha256').update(str).digest('hex').slice(0, 12);
    return `[redacted:sha256:${digest}]`;
  }

  /**
   * Scrub string values that *look like* credentials regardless of key.
   * Catches the case where a future error message includes a raw
   * `Authorization: Token …` substring (the audit's H-8 / H-9 chain).
   */
  private scrubStringValue(value: string): string {
    let out = value;
    for (const pattern of SENSITIVE_VALUE_PATTERNS) {
      out = out.replace(pattern, match => {
        const digest = createHash('sha256')
          .update(match)
          .digest('hex')
          .slice(0, 12);
        return `[redacted:sha256:${digest}]`;
      });
    }
    return out;
  }

  private output(entry: LogEntry): void {
    const logString = JSON.stringify(entry);
    // Always write to stderr in MCP server to avoid polluting stdout JSON-RPC channel.
    // Note: real newline, not the escaped literal that the previous version emitted
    // (which made all log lines concatenate into one giant stderr line).
    process.stderr.write(`${logString}\n`);
  }

  error(
    message: string,
    error?: Error,
    metadata?: Record<string, unknown>,
    traceId?: string,
    requestId?: string
  ): void {
    if (!this.shouldLog('error')) {
      return;
    }

    const entry = this.createLogEntry(
      'error',
      message,
      metadata,
      error,
      traceId,
      requestId
    );
    this.output(entry);
  }

  warn(
    message: string,
    metadata?: Record<string, unknown>,
    traceId?: string,
    requestId?: string
  ): void {
    if (!this.shouldLog('warn')) {
      return;
    }

    const entry = this.createLogEntry(
      'warn',
      message,
      metadata,
      undefined,
      traceId,
      requestId
    );
    this.output(entry);
  }

  info(
    message: string,
    metadata?: Record<string, unknown>,
    traceId?: string,
    requestId?: string
  ): void {
    if (!this.shouldLog('info')) {
      return;
    }

    const entry = this.createLogEntry(
      'info',
      message,
      metadata,
      undefined,
      traceId,
      requestId
    );
    this.output(entry);
  }

  debug(
    message: string,
    metadata?: Record<string, unknown>,
    traceId?: string,
    requestId?: string
  ): void {
    if (!this.shouldLog('debug')) {
      return;
    }

    const entry = this.createLogEntry(
      'debug',
      message,
      metadata,
      undefined,
      traceId,
      requestId
    );
    this.output(entry);
  }

  // Namespace-specific debug logging
  debugNamespace(
    namespace: string,
    message: string,
    metadata?: Record<string, unknown>,
    traceId?: string,
    requestId?: string
  ): void {
    if (!shouldDebug(namespace)) {
      return;
    }

    const namespacedMessage = `[${namespace}] ${message}`;
    const entry = this.createLogEntry(
      'debug',
      namespacedMessage,
      metadata,
      undefined,
      traceId,
      requestId
    );
    this.output(entry);
  }

  // Convenience methods for common scenarios
  apiRequest(
    method: string,
    endpoint: string,
    duration: number,
    statusCode: number,
    requestId?: string
  ): void {
    this.info(
      'API request completed',
      {
        http: {
          method,
          endpoint,
          duration_ms: duration,
          status_code: statusCode,
        },
      },
      undefined,
      requestId
    );
  }

  apiError(
    method: string,
    endpoint: string,
    error: Error,
    requestId?: string
  ): void {
    this.error(
      'API request failed',
      error,
      {
        http: {
          method,
          endpoint,
        },
      },
      undefined,
      requestId
    );
  }

  securityEvent(event: string, metadata: Record<string, unknown>): void {
    this.warn('Security event detected', {
      security: {
        event,
        ...metadata,
      },
    });
  }

  cacheOperation(
    operation: string,
    key: string,
    hit: boolean,
    metadata?: Record<string, unknown>
  ): void {
    this.debugNamespace(
      'cache',
      `Cache ${operation}: ${hit ? 'HIT' : 'MISS'}`,
      {
        cache: {
          operation,
          key,
          hit,
          ...metadata,
        },
      }
    );
  }

  // Performance monitoring logs
  performanceLog(
    operation: string,
    duration: number,
    metadata?: Record<string, unknown>
  ): void {
    this.debugNamespace(
      'performance',
      `${operation} completed in ${duration}ms`,
      {
        performance: {
          operation,
          duration_ms: duration,
          ...metadata,
        },
      }
    );
  }

  // Data pipeline troubleshooting logs
  pipelineLog(
    stage: string,
    message: string,
    metadata?: Record<string, unknown>
  ): void {
    this.debugNamespace('pipeline', `[${stage}] ${message}`, {
      pipeline: {
        stage,
        ...metadata,
      },
    });
  }

  // Query performance logs
  queryLog(
    queryType: string,
    query: string,
    duration: number,
    resultCount: number,
    metadata?: Record<string, unknown>
  ): void {
    this.debugNamespace('query', `${queryType} query executed`, {
      query: {
        type: queryType,
        query: query.length > 100 ? `${query.substring(0, 100)}...` : query,
        duration_ms: duration,
        result_count: resultCount,
        ...metadata,
      },
    });
  }
}

// Global logger instance
export const logger = new StructuredLogger();
