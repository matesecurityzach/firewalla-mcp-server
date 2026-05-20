/**
 * @fileoverview MCP Tool Setup and Registry Management
 *
 * Wires the ToolRegistry into the MCP server. The registry holds 37 tools
 * across the categories below; the full per-tool list lives in
 * `src/tools/registry.ts`.
 *
 * Categories:
 * - security (2): alarm retrieval (get_active_alarms, get_specific_alarm)
 * - network (3): flow data + bandwidth + offline-device wrappers
 * - device (1): get_device_status
 * - rule (9): rule + target-list CRUD + rules summary wrapper
 * - analytics (13): box/region stats, flow insights, trends, plus the 5
 *   report composite tools (generate_*)
 * - search (5): search_flows/alarms/rules/devices/target_lists
 * - investigation (4): investigate_ip, investigate_device,
 *   get_alarm_context, get_target_timeline
 */

import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import type { FirewallaClient } from '../firewalla/client.js';
import { createErrorResponse, ErrorType } from '../validation/error-handler.js';
import { logger } from '../monitoring/logger.js';
import { ToolRegistry } from './registry.js';
import { getCurrentTimestamp } from '../utils/timestamp.js';

import { metrics } from '../monitoring/metrics.js';

/**
 * Registers and configures all Firewalla MCP tools on the server using a modular registry pattern
 *
 * Sets up the complete toolkit of 37 firewall + investigation tools, each encapsulated
 * in its own handler class and organized by functional category. The registry pattern provides
 * clean separation of concerns and enables easy testing and maintenance.
 *
 * Key Features:
 * - Automated tool discovery and registration through ToolRegistry
 * - Centralized error handling with detailed diagnostic information
 * - Category-based organization for better tool discoverability
 * - Comprehensive logging for debugging and monitoring
 * - Type-safe tool execution with parameter validation
 *
 * @param server - The MCP server instance where tools will be registered
 * @param firewalla - Authenticated Firewalla client for API communication
 * @returns {void}
 *
 * @example
 * ```typescript
 * const server = new Server({ name: 'firewalla-mcp' });
 * const client = new FirewallaClient(config);
 * setupTools(server, client);
 *
 * // Tools are now available for MCP clients:
 * // - get_active_alarms, search_flows, get_device_status, etc.
 * ```
 *
 * @public
 */
export function setupTools(server: Server, firewalla: FirewallaClient): void {
  // Initialize the tool registry with all 37 handlers
  const toolRegistry = new ToolRegistry();

  // Set up the main request handler using the registry
  server.setRequestHandler(CallToolRequestSchema, async request => {
    const { name, arguments: args } = request.params;

    const startTime = Date.now();

    try {
      // Get handler from the registry
      const handler = toolRegistry.getHandler(name);
      if (!handler) {
        const availableTools = toolRegistry.getToolNames() || [];
        throw new Error(
          `Unknown tool: ${name}. Available tools: ${availableTools.join(', ')}`
        );
      }

      // Execute the tool handler with proper error handling
      logger.debug(
        `Executing tool: ${name} with handler: ${handler.constructor.name}`
      );
      const response = await handler.execute(args || {}, firewalla);

      // <add success telemetry>
      metrics.count('tool.success');
      metrics.timing('tool.latency_ms', Date.now() - startTime);
      // </add>

      return response;
    } catch (error: unknown) {
      // <add error metric>
      metrics.count('tool.error');
      // </add>
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error occurred';
      logger.error(`Tool execution failed for ${name}:`, error as Error);

      // Use centralized error handling
      return createErrorResponse(name, errorMessage, ErrorType.UNKNOWN_ERROR, {
        timestamp: getCurrentTimestamp(),
        error_type:
          error instanceof Error ? error.constructor.name : 'UnknownError',
        available_tools: toolRegistry.getToolNames() || [],
      });
    }
  });

  const allToolNames = toolRegistry.getToolNames() || [];
  const categories = [
    'security',
    'network',
    'device',
    'rule',
    'analytics',
    'search',
  ];
  const totalCategories = categories.length;

  logger.info(
    `MCP tools setup complete. Registry contains ${allToolNames.length} handlers across ${totalCategories} categories.`
  );
  logger.info(`Registered tools: ${allToolNames.join(', ')}`);
}

/**
 * Tool registry overview (37 tools across 7 categories).
 * See src/tools/registry.ts for the canonical, up-to-date list.
 */
