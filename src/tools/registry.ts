/**
 * @fileoverview Tool Registry
 *
 * Registry of all MCP tool handlers exposed by the Firewalla MCP server.
 *
 * Tool distribution (37 total):
 *
 * Direct API tools (15):
 *   - Security (2): get_active_alarms, get_specific_alarm.
 *     Note: delete_alarm is implemented (DeleteAlarmHandler in handlers/security.ts)
 *     but intentionally NOT registered because the MSP API returns success
 *     without actually deleting.
 *   - Network (1): get_flow_data
 *   - Device (1): get_device_status
 *   - Rules (8): get_network_rules, pause_rule, resume_rule, get_target_lists,
 *     get_specific_target_list, create_target_list, update_target_list,
 *     delete_target_list
 *   - Search (3): search_flows, search_alarms, search_rules
 *
 * Analytics (8): get_boxes, get_simple_statistics, get_statistics_by_region,
 *   get_statistics_by_box, get_recent_flow_activity, get_flow_insights,
 *   get_alarm_trends, get_rule_trends.
 *
 * Convenience wrappers (5): get_bandwidth_usage, get_offline_devices,
 *   search_devices, search_target_lists, get_network_rules_summary.
 *
 * Investigation composite tools (4): investigate_ip, investigate_device,
 *   get_alarm_context, get_target_timeline.
 *
 * Report composite tools (5): generate_security_report,
 *   generate_threat_analysis, generate_bandwidth_analysis_report,
 *   generate_device_investigation_report, generate_network_health_report.
 *
 * Adding a new tool requires three coordinated edits: (1) implement the
 * handler in src/tools/handlers/<category>.ts; (2) register it here; (3) add
 * its schema to the ListTools block in src/server.ts. The agent investigation
 * guide and README should be updated when the public surface changes.
 */

import type { ToolHandler } from './handlers/base.js';
import {
  GetActiveAlarmsHandler,
  GetSpecificAlarmHandler,
  // DeleteAlarmHandler, // Disabled - API returns false success
} from './handlers/security.js';
import {
  GetFlowDataHandler,
  GetBandwidthUsageHandler,
  GetOfflineDevicesHandler,
} from './handlers/network.js';
import { GetDeviceStatusHandler } from './handlers/device.js';
import {
  GetNetworkRulesHandler,
  PauseRuleHandler,
  ResumeRuleHandler,
  GetTargetListsHandler,
  GetSpecificTargetListHandler,
  CreateTargetListHandler,
  UpdateTargetListHandler,
  DeleteTargetListHandler,
  GetNetworkRulesSummaryHandler,
} from './handlers/rules.js';
import {
  GetBoxesHandler,
  GetSimpleStatisticsHandler,
  GetStatisticsByRegionHandler,
  GetStatisticsByBoxHandler,
  GetRecentFlowActivityHandler,
  GetFlowInsightsHandler,
  GetAlarmTrendsHandler,
  GetRuleTrendsHandler,
} from './handlers/analytics.js';
import {
  SearchFlowsHandler,
  SearchAlarmsHandler,
  SearchRulesHandler,
  SearchDevicesHandler,
  SearchTargetListsHandler,
} from './handlers/search.js';
import {
  InvestigateIpHandler,
  InvestigateDeviceHandler,
  GetAlarmContextHandler,
  GetTargetTimelineHandler,
} from './handlers/investigation.js';
import {
  GenerateSecurityReportHandler,
  GenerateThreatAnalysisHandler,
  GenerateBandwidthAnalysisHandler,
  GenerateDeviceInvestigationReportHandler,
  GenerateNetworkHealthReportHandler,
} from './handlers/reports.js';

/**
 * Central registry for managing all MCP tool handlers.
 *
 * Registers the full 37-tool surface (23 direct API + 5 convenience wrappers
 * + 4 investigation composite tools + 5 report composite tools) and exposes
 * lookup helpers by name and by category.
 *
 * @example
 * ```typescript
 * const registry = new ToolRegistry();
 *
 * // Get a specific tool
 * const alarmHandler = registry.getHandler('get_active_alarms');
 *
 * // Get tools by category
 * const investigationTools = registry.getToolsByCategory('investigation');
 *
 * // List every registered tool
 * const allTools = registry.getToolNames();
 * ```
 *
 * @class
 * @public
 */
export class ToolRegistry {
  /** @private Map storing tool name to handler instances */
  private handlers = new Map<string, ToolHandler>();

  /**
   * Creates a new tool registry and automatically registers all available handlers
   *
   * @constructor
   */
  constructor() {
    this.registerHandlers();
  }

  /**
   * Registers all 37 tool handlers (23 direct API + 5 convenience wrappers
   * + 4 investigation composite + 5 report composite). See the file-level
   * JSDoc above for the full tool list.
   *
   * @private
   */
  private registerHandlers(): void {
    // Security tools (2 handlers - delete_alarm disabled)
    this.register(new GetActiveAlarmsHandler());
    this.register(new GetSpecificAlarmHandler());
    // Disabled: DeleteAlarmHandler commented out because the Firewalla MSP API
    // returns false success responses but doesn't actually delete alarms
    // this.register(new DeleteAlarmHandler());

    // Network tools (1 handler - get_flow_data)
    this.register(new GetFlowDataHandler());

    // Device tools (1 handler)
    this.register(new GetDeviceStatusHandler());

    // Rule tools (8 handlers)
    this.register(new GetNetworkRulesHandler());
    this.register(new PauseRuleHandler());
    this.register(new ResumeRuleHandler());
    this.register(new GetTargetListsHandler());
    this.register(new GetSpecificTargetListHandler());
    this.register(new CreateTargetListHandler());
    this.register(new UpdateTargetListHandler());
    this.register(new DeleteTargetListHandler());

    // Search tools (3 handlers)
    this.register(new SearchFlowsHandler());
    this.register(new SearchAlarmsHandler());
    this.register(new SearchRulesHandler());

    // Analytics tools (8 handlers)
    this.register(new GetBoxesHandler());
    this.register(new GetSimpleStatisticsHandler());
    this.register(new GetStatisticsByRegionHandler());
    this.register(new GetStatisticsByBoxHandler());
    this.register(new GetRecentFlowActivityHandler());
    this.register(new GetFlowInsightsHandler());
    this.register(new GetAlarmTrendsHandler());
    this.register(new GetRuleTrendsHandler());

    // Convenience Wrappers (5 handlers)
    this.register(new GetBandwidthUsageHandler()); // wrapper around get_device_status
    this.register(new GetOfflineDevicesHandler()); // wrapper around get_device_status
    this.register(new SearchDevicesHandler()); // wrapper with client-side filtering
    this.register(new SearchTargetListsHandler()); // wrapper with client-side filtering
    this.register(new GetNetworkRulesSummaryHandler()); // wrapper around get_network_rules

    // Investigation composite tools (4 handlers) - fan out to multiple client
    // calls and return a single correlated payload. Designed for AI agents.
    this.register(new InvestigateIpHandler());
    this.register(new InvestigateDeviceHandler());
    this.register(new GetAlarmContextHandler());
    this.register(new GetTargetTimelineHandler());

    // Report composite tools (5 handlers) - agent-callable equivalents of the
    // MCP prompts. Return { data, narrative }.
    this.register(new GenerateSecurityReportHandler());
    this.register(new GenerateThreatAnalysisHandler());
    this.register(new GenerateBandwidthAnalysisHandler());
    this.register(new GenerateDeviceInvestigationReportHandler());
    this.register(new GenerateNetworkHealthReportHandler());
  }

  /**
   * Registers a single tool handler in the registry
   *
   * Includes duplicate registration protection to prevent accidental overwrites
   * and ensure tool registry integrity. If a tool with the same name is already
   * registered, this method will throw an error with diagnostic information.
   *
   * @param handler - The tool handler instance to register
   * @throws {Error} If a handler with the same name is already registered
   * @returns {void}
   * @public
   */
  register(handler: ToolHandler): void {
    if (this.handlers.has(handler.name)) {
      const existingHandler = this.handlers.get(handler.name);
      throw new Error(
        `Tool registration conflict: A handler named '${handler.name}' is already registered. ` +
          `Existing handler category: '${existingHandler?.category}', ` +
          `New handler category: '${handler.category}'. ` +
          `Tool names must be unique across the registry.`
      );
    }

    this.handlers.set(handler.name, handler);
  }

  /**
   * Forcefully registers a tool handler, replacing any existing handler with the same name
   *
   * Use this method only when you explicitly want to replace an existing handler.
   * This bypasses the duplicate registration protection for testing or dynamic
   * handler replacement scenarios.
   *
   * @param handler - The tool handler instance to register
   * @param reason - Optional reason for the forced registration (for logging)
   * @returns {string | null} Name of the replaced handler if any, null otherwise
   * @public
   */
  forceRegister(handler: ToolHandler, reason?: string): string | null {
    const existingHandler = this.handlers.get(handler.name);

    if (existingHandler && reason) {
      // Optional logging for forced replacements using stderr to avoid no-console lint issue
      process.stderr.write(
        `[WARNING] Forced tool registration: Replacing '${handler.name}' ` +
          `(${existingHandler.category} -> ${handler.category}). Reason: ${reason}\n`
      );
    }

    this.handlers.set(handler.name, handler);
    return existingHandler ? existingHandler.name : null;
  }

  /**
   * Retrieves a tool handler by its registered name
   *
   * @param toolName - The name of the tool to retrieve
   * @returns The tool handler if found, undefined otherwise
   * @public
   */
  getHandler(toolName: string): ToolHandler | undefined {
    return this.handlers.get(toolName);
  }

  /**
   * Gets a list of all registered tool names
   *
   * Useful for tool discovery, error messages, and debugging.
   *
   * @returns Array of all registered tool names
   * @public
   */
  getToolNames(): string[] {
    return Array.from(this.handlers.keys());
  }

  /**
   * Retrieves all tools belonging to a specific category
   *
   * Categories include: 'security', 'network', 'device', 'rule', 'analytics', 'search'
   *
   * @param category - The category to filter by
   * @returns Array of tool handlers in the specified category
   * @public
   */
  getToolsByCategory(category: string): ToolHandler[] {
    return Array.from(this.handlers.values()).filter(
      handler => handler.category === category
    );
  }

  /**
   * Checks if a tool with the given name is registered
   *
   * @param toolName - The tool name to check
   * @returns True if the tool is registered, false otherwise
   * @public
   */
  isRegistered(toolName: string): boolean {
    return this.handlers.has(toolName);
  }
}
