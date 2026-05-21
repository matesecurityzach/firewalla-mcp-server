#!/usr/bin/env node

/**
 * @fileoverview Firewalla MCP Server
 *
 * This file implements the primary MCP server class that provides MCP clients
 * (including AI security-investigation agents) with access to Firewalla data
 * through 37 tools, 9 resources, and 5 prompts.
 *
 * Tool layout:
 * - 23 direct API tools (alarms, flows, devices, rules, target lists, analytics)
 * - 5 convenience wrappers (bandwidth, offline devices, search wrappers, rule summary)
 * - 4 investigation composite tools (investigate_ip, investigate_device,
 *   get_alarm_context, get_target_timeline)
 * - 5 report composite tools (generate_security_report, generate_threat_analysis,
 *   generate_bandwidth_analysis_report, generate_device_investigation_report,
 *   generate_network_health_report)
 *
 * Resources include live data (summary, devices, metrics/security, topology,
 * threats/recent, boxes) and static reference (alarm-types, categories,
 * query-syntax).
 *
 * Architecture features:
 * - Limits aligned to API maximum (500)
 * - Required parameters for direct API calls
 * - CRUD operations for target lists
 * - Dual transport support (stdio and HTTP)
 *
 * @version 1.2.0
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  ListToolsRequestSchema,
  isInitializeRequest,
} from '@modelcontextprotocol/sdk/types.js';
import { randomUUID, timingSafeEqual } from 'node:crypto';
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from 'node:http';
import { config } from './config/config.js';
import { FirewallaClient } from './firewalla/client.js';
import { setupTools } from './tools/index.js';
import { setupResources } from './resources/index.js';
import { setupPrompts } from './prompts/index.js';
import { logger } from './monitoring/logger.js';
import { SecurityManager } from './config/security.js';

/**
 * UUID v4 validation regex pattern
 */
const UUID_V4_REGEX =
  /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/**
 * Validates that a string is a properly formatted UUID v4
 *
 * @param value - The string to validate
 * @returns True if the value is a valid UUID v4, false otherwise
 */
function isValidUUID(value: string): boolean {
  return UUID_V4_REGEX.test(value);
}

/**
 * Main MCP Server class for Firewalla integration with 28-tool architecture
 */
export class FirewallaMCPServer {
  private static signalHandlersRegistered = false;

  private server: Server;
  private firewalla: FirewallaClient;
  private security: SecurityManager;

  constructor() {
    this.server = this.createServerInstance();
    this.firewalla = new FirewallaClient(config);
    this.security = new SecurityManager();
    this.setupHandlers(this.server);
  }

  /**
   * Constructs a fresh MCP Server instance with the project's capability
   * declarations. Each call returns a distinct instance — for HTTP transport
   * we instantiate one per session so that responses from session A cannot be
   * routed to session B (closes GHSA-345p-7cg4-v4c7).
   */
  private createServerInstance(): Server {
    return new Server(
      {
        name: 'firewalla-mcp-server',
        version: '1.2.0',
      },
      {
        capabilities: {
          tools: {},
          resources: {},
          prompts: {},
        },
      }
    );
  }

  /**
   * Sets up MCP protocol request handlers on the given Server instance.
   * Accepts the target server so callers can attach handlers to per-session
   * Server instances (HTTP transport) or the single shared instance (stdio).
   */
  private setupHandlers(targetServer: Server): void {
    // List available tools - 28-Tool Complete API Coverage
    targetServer.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          // Direct API Endpoints (24 tools)
          {
            name: 'get_active_alarms',
            description:
              'Retrieve current security alerts and alarms. Investigation use: starting point for "what is firing right now?" - returns full alarm objects including device and remote-host context. For correlation across an IP or device, prefer investigate_ip or get_alarm_context. Browse firewalla://reference/alarm-types for the full type id->name table.',
            inputSchema: {
              type: 'object',
              properties: {
                query: {
                  type: 'string',
                  description:
                    'Firewalla MSP query. Verified qualifiers: type:1-16 (or AlarmType:"Security Activity"), status:active|archived, ts:>UNIX|<UNIX|RANGE, box.id:UUID, box.name:"My Firewalla", device.id:"mac:AA:BB:CC:DD:EE:FF", device.name:*iphone*, device.network.name:Guest, remote.domain:*.facebook.com, remote.region:US, remote.category:porn|games|social|..., transfer.total:>50MB, transfer.download:>10MB, transfer.upload:>10MB. Combine terms with spaces (implicit-AND grammar). Use - prefix to exclude (e.g. -status:archived). Examples: "type:1 status:active", "remote.region:CN type:1", "device.name:*laptop* transfer.total:>100MB".',
                },
                groupBy: {
                  type: 'string',
                  description: 'Group alarms by field (e.g., type, box)',
                },
                sortBy: {
                  type: 'string',
                  description: 'Sort alarms (default: ts:desc)',
                },
                limit: {
                  type: 'number',
                  description:
                    'Results per page (optional, default: 200, API maximum: 500)',
                  minimum: 1,
                  maximum: 500,
                  default: 200,
                },
                cursor: {
                  type: 'string',
                  description: 'Pagination cursor from previous response',
                },
              },
              required: [],
            },
          },
          {
            name: 'get_specific_alarm',
            description:
              'Fetch one full alarm record by its alarm id (aid). Returns the alarm plus device + remote context. Required: alarm_id. Where to get alarm_id: the "aid" field on any item returned by get_active_alarms or search_alarms. For an alarm plus its sibling alarms (same device / same remote / same type within a time window), prefer get_alarm_context.',
            inputSchema: {
              type: 'object',
              properties: {
                alarm_id: {
                  type: 'string',
                  description:
                    'Required. The alarm id (aid) as returned by get_active_alarms or search_alarms. Format varies by Firewalla version; pass through verbatim. Example: "abcdef01-2345-6789-abcd-ef0123456789".',
                },
              },
              required: ['alarm_id'],
            },
          },
          // Disabled: delete_alarm tool commented out because the Firewalla MSP API
          // returns false success responses but doesn't actually delete alarms
          // {
          //   name: 'delete_alarm',
          //   description: 'Delete/dismiss a specific Firewalla alarm',
          //   inputSchema: {
          //     type: 'object',
          //     properties: {
          //       alarm_id: {
          //         type: 'string',
          //         description: 'Alarm ID (required for API call)',
          //       },
          //     },
          //     required: ['alarm_id'],
          //   },
          // },
          {
            name: 'get_flow_data',
            description:
              'Query raw network traffic flow records (bidirectional connections between devices and remote hosts). Investigation use: direct passthrough to /v2/flows when you already know the filter shape. For an IP-centric or device-centric correlation across alarms + rules + flows in one call, prefer investigate_ip or investigate_device.',
            inputSchema: {
              type: 'object',
              properties: {
                query: {
                  type: 'string',
                  description:
                    'Firewalla MSP query. Verified qualifiers: ts:>UNIX|<UNIX|RANGE, direction:inbound|outbound|local, protocol:tcp|udp, status:ok, box.id:UUID, box.name:..., device.id:"mac:AA:BB:CC:DD:EE:FF", device.name:*phone*, network.name:Guest, domain:*.example.com, region:US (ISO-3166), category:ad|edu|games|gamble|intel|p2p|porn|private|social|shopping|video|vpn, sport:53, dport:443, download:>10MB, upload:>10MB, total:>50MB. Combine terms with spaces (implicit-AND grammar); list multiple values for one qualifier using commas (e.g. category:porn,gamble). Use - prefix to exclude. Examples: "region:CN direction:outbound", "category:porn,gamble -status:ok", "device.name:*laptop* total:>100MB".',
                },
                groupBy: {
                  type: 'string',
                  description:
                    'Group flows by specified values (e.g., "domain,box")',
                },
                sortBy: {
                  type: 'string',
                  description: 'Sort flows (default: "ts:desc")',
                },
                limit: {
                  type: 'number',
                  description:
                    'Maximum results (optional, default: 200, API maximum: 500)',
                  minimum: 1,
                  maximum: 500,
                  default: 200,
                },
                cursor: {
                  type: 'string',
                  description: 'Pagination cursor from previous response',
                },
              },
              required: [],
            },
          },
          {
            name: 'get_device_status',
            description:
              'List devices on the network with current online/offline status, IP, MAC vendor, network, group, and bytes counters. Investigation use: device inventory pull. For "what has device X been doing?" prefer investigate_device. Required: limit. Default scope: all boxes the MSP token can see (or the box pinned by FIREWALLA_BOX_ID).',
            inputSchema: {
              type: 'object',
              properties: {
                limit: {
                  type: 'number',
                  description:
                    'Required. Maximum number of devices to return (1-1000). Start with 100 and paginate via search_devices if you need more.',
                  minimum: 1,
                  maximum: 1000,
                },
                box: {
                  type: 'string',
                  description:
                    'Optional. Box GID (UUID). Restricts results to one Firewalla box. Get from get_boxes (each box has a "gid" field). Example: "1eb71e38-3a95-4b13-922d-542b84e9bbe3".',
                },
                group: {
                  type: 'string',
                  description:
                    'Optional. Box group id. Restricts results to one box group. Get from get_boxes (each box has a "group.id" field when grouped).',
                },
              },
              required: ['limit'],
            },
          },
          {
            name: 'get_network_rules',
            description:
              'Retrieve firewall rules (allow / block / time-limit policies). Required: limit. Optional query is passed straight through to the MSP API; only verified MSP rule qualifiers will match server-side. For richer client-side filtering (target.type, target.value, scope, etc.), use search_rules. For an overview by category, use get_network_rules_summary.',
            inputSchema: {
              type: 'object',
              properties: {
                limit: {
                  type: 'number',
                  description:
                    'Required. Maximum number of rules to return (1-1000).',
                  minimum: 1,
                  maximum: 1000,
                },
                query: {
                  type: 'string',
                  description:
                    'Optional Firewalla MSP rule query, passed verbatim to the API. Verified qualifiers: status:active|paused, action:allow|block|timelimit, box.id:UUID, box.group.id:GROUPID, device.id:"mac:AA:BB:CC:DD:EE:FF". Combine with spaces (implicit-AND). Examples: "status:active action:block", "box.id:1eb71e38-...". For broader filtering (target.value:*.facebook.com, target.type, scope.type, etc.) use search_rules instead.',
                },
              },
              required: ['limit'],
            },
          },
          {
            name: 'pause_rule',
            description:
              'WRITE OPERATION. Temporarily disable an active firewall rule for a fixed duration; it auto-resumes when the timer expires. Required: rule_id, box. Pre-check the rule with search_rules (query "id:<rule_id>") if you are unsure of its current status — pausing an already-paused rule returns an error. To extend a pause, resume first then call pause_rule again.',
            inputSchema: {
              type: 'object',
              properties: {
                rule_id: {
                  type: 'string',
                  description:
                    'Required. The rule id (pid) returned in the "id" field by get_network_rules / search_rules. Pass through verbatim.',
                },
                duration: {
                  type: 'number',
                  description:
                    'Optional. Pause duration in MINUTES (1-1440, default 60). The rule auto-resumes when this elapses; there is no way to pause indefinitely.',
                  minimum: 1,
                  maximum: 1440,
                  default: 60,
                },
                box: {
                  type: 'string',
                  description:
                    'Required. Box GID (UUID) that owns this rule. Get from get_boxes or from the rule object\'s "box.id" field.',
                },
              },
              required: ['rule_id', 'box'],
            },
          },
          {
            name: 'resume_rule',
            description:
              'WRITE OPERATION. Resume a previously paused firewall rule, restoring it to active state immediately. Required: rule_id, box. No-op if the rule is already active.',
            inputSchema: {
              type: 'object',
              properties: {
                rule_id: {
                  type: 'string',
                  description:
                    'Required. The rule id (pid) returned in the "id" field by get_network_rules / search_rules.',
                },
                box: {
                  type: 'string',
                  description:
                    'Required. Box GID (UUID) that owns this rule. Get from get_boxes or from the rule object\'s "box.id" field.',
                },
              },
              required: ['rule_id', 'box'],
            },
          },
          {
            name: 'get_target_lists',
            description:
              'List all target lists (named, reusable bundles of domains / IPs / CIDR ranges used by firewall rules). Required: limit. Returns each list\'s id, name, owner, category, target count, and member entries. For client-side filtering by name/category/owner/targets, use search_target_lists.',
            inputSchema: {
              type: 'object',
              properties: {
                limit: {
                  type: 'number',
                  description:
                    'Required. Maximum number of target lists to return (1-1000).',
                  minimum: 1,
                  maximum: 1000,
                },
              },
              required: ['limit'],
            },
          },
          {
            name: 'get_specific_target_list',
            description:
              'Fetch one target list by its id, including the full member list (every domain / IP / CIDR in the bundle). Required: id. Use get_target_lists or search_target_lists to discover ids.',
            inputSchema: {
              type: 'object',
              properties: {
                id: {
                  type: 'string',
                  description:
                    'Required. Target list id as returned by get_target_lists ("id" field). Pass through verbatim. Example: "TL-built-in-1".',
                },
              },
              required: ['id'],
            },
          },
          {
            name: 'create_target_list',
            description:
              'WRITE OPERATION. Create a new target list (a reusable bundle of domains / IPs / CIDR ranges that firewall rules can reference by id). Required: name, owner, targets. The returned object includes the new "id" — use it to reference the list from rules. To add entries to an existing list later, use update_target_list (full replacement of the targets array).',
            inputSchema: {
              type: 'object',
              properties: {
                name: {
                  type: 'string',
                  description:
                    'Required. Display name (max 24 chars). Example: "Block Social Media".',
                  maxLength: 24,
                },
                owner: {
                  type: 'string',
                  description:
                    'Required. Scope: "global" (visible to every box on the MSP account) or a box GID (UUID) to restrict to a single Firewalla. Get box GIDs from get_boxes.',
                },
                targets: {
                  type: 'array',
                  items: {
                    type: 'string',
                  },
                  description:
                    'Required. Array of entries; each is a domain (e.g. "facebook.com" or "*.facebook.com"), IPv4/IPv6 address ("1.2.3.4"), or CIDR range ("192.168.1.0/24"). At least one entry.',
                },
                category: {
                  type: 'string',
                  enum: [
                    'ad',
                    'edu',
                    'games',
                    'gamble',
                    'intel',
                    'p2p',
                    'porn',
                    'private',
                    'social',
                    'shopping',
                    'video',
                    'vpn',
                  ],
                  description:
                    'Optional. Content category — drives default UX grouping. See firewalla://reference/categories.',
                },
                notes: {
                  type: 'string',
                  description:
                    'Optional. Free-form description shown in the Firewalla UI.',
                },
              },
              required: ['name', 'owner', 'targets'],
            },
          },
          {
            name: 'update_target_list',
            description:
              'WRITE OPERATION. Update an existing target list. Required: id. All other fields are optional; only the fields you pass are changed. IMPORTANT: passing `targets` REPLACES the entire member list — to add one entry, first fetch the list with get_specific_target_list, append, and send back the full array.',
            inputSchema: {
              type: 'object',
              properties: {
                id: {
                  type: 'string',
                  description:
                    'Required. Target list id from get_target_lists.',
                },
                name: {
                  type: 'string',
                  description:
                    'Optional. Updated display name (max 24 chars).',
                  maxLength: 24,
                },
                targets: {
                  type: 'array',
                  items: {
                    type: 'string',
                  },
                  description:
                    'Optional. FULL REPLACEMENT array of domains / IPs / CIDR ranges. To append, read the list first then send the merged array.',
                },
                category: {
                  type: 'string',
                  enum: [
                    'ad',
                    'edu',
                    'games',
                    'gamble',
                    'intel',
                    'p2p',
                    'porn',
                    'private',
                    'social',
                    'shopping',
                    'video',
                    'vpn',
                  ],
                  description:
                    'Optional. Updated content category. See firewalla://reference/categories.',
                },
                notes: {
                  type: 'string',
                  description: 'Optional. Updated free-form description.',
                },
              },
              required: ['id'],
            },
          },
          {
            name: 'delete_target_list',
            description:
              'WRITE OPERATION (destructive). Permanently delete a target list. Required: id. Any firewall rule referencing this list will lose its target set — verify nothing critical depends on it (search_rules query "target.value:<list_id>") before calling.',
            inputSchema: {
              type: 'object',
              properties: {
                id: {
                  type: 'string',
                  description:
                    'Required. Target list id to delete (from get_target_lists).',
                },
              },
              required: ['id'],
            },
          },
          {
            name: 'search_flows',
            description:
              'Search network flows with advanced query filters, pagination, time-windowing, and geographic filters. Investigation use: historical traffic analysis, complex filtering, anything beyond the 50-flow snapshot from get_recent_flow_activity. For correlation across an IP/device in one payload, prefer investigate_ip / investigate_device.',
            inputSchema: {
              type: 'object',
              properties: {
                query: {
                  type: 'string',
                  description:
                    'Firewalla MSP flow query. Verified qualifiers: ts:>UNIX|<UNIX|RANGE, direction:inbound|outbound|local, protocol:tcp|udp, status:ok, box.id:UUID, box.name:..., device.id:"mac:AA:BB:CC:DD:EE:FF", device.name:*phone*, network.name:..., domain:*.example.com, region:US, category:ad|edu|games|gamble|intel|p2p|porn|private|social|shopping|video|vpn, sport:53, dport:443, download:>10MB, upload:>10MB, total:>50MB. Combine terms with spaces (implicit-AND grammar); list multiple values for one qualifier using commas (e.g. category:porn,gamble). Use - prefix to exclude. Examples: "region:CN direction:outbound total:>1MB", "category:porn,gamble", "-status:ok device.name:*server*". For grammar reference, read resource firewalla://reference/query-syntax.',
                },
                groupBy: {
                  type: 'string',
                  description:
                    'Group flows by specified values (e.g., "domain,box")',
                },
                sortBy: {
                  type: 'string',
                  description: 'Sort flows (default: "ts:desc")',
                },
                limit: {
                  type: 'number',
                  description:
                    'Maximum results (optional, default: 200, API maximum: 500)',
                  minimum: 1,
                  maximum: 500,
                  default: 200,
                },
                cursor: {
                  type: 'string',
                  description: 'Pagination cursor from previous response',
                },
              },
              required: [],
            },
          },
          {
            name: 'search_alarms',
            description:
              'Search alarms by field filters with pagination and grouping. Alarm types (also see resource firewalla://reference/alarm-types): 1=Security Activity, 2=Abnormal Upload, 3=Large Bandwidth Usage, 4=Monthly Data Plan, 5=New Device, 6=Device Back Online, 7=Device Offline, 8=Video Activity, 9=Gaming Activity, 10=Porn Activity, 11=VPN Activity, 12=VPN Connection Restored, 13=VPN Connection Error, 14=Open Port, 15=Internet Connectivity Update, 16=Large Upload. Investigation use: hunt across alarms by attribute. For one-alarm-plus-related-alarms, prefer get_alarm_context.',
            inputSchema: {
              type: 'object',
              properties: {
                query: {
                  type: 'string',
                  description:
                    'Firewalla MSP alarm query. Verified qualifiers: ts:>UNIX|<UNIX|RANGE, type:1-16 (or AlarmType:"Security Activity,Abnormal Upload"), status:active|archived, box.id:UUID, box.name:..., box.group.id:GROUPID, device.id:"mac:AA:BB:CC:DD:EE:FF", device.name:*iphone*, device.network.name:Guest, remote.category:porn|games|social|..., remote.domain:*.facebook.com, remote.region:US, transfer.download:>10MB, transfer.upload:>10MB, transfer.total:>50MB. Combine terms with spaces (implicit-AND grammar); list multiple values for one qualifier using commas (e.g. type:1,2). Use - prefix to exclude (e.g. -status:archived). Examples: "type:1 remote.region:CN", "type:10 status:active", "device.name:*kids* remote.category:gamble", "type:1 -remote.region:US".',
                },
                groupBy: {
                  type: 'string',
                  description:
                    'Group alarms by specified fields (comma-separated)',
                },
                sortBy: {
                  type: 'string',
                  description: 'Sort alarms (default: ts:desc)',
                },
                limit: {
                  type: 'number',
                  description:
                    'Maximum results (optional, default: 200, API maximum: 500)',
                  minimum: 1,
                  maximum: 500,
                  default: 200,
                },
                cursor: {
                  type: 'string',
                  description: 'Pagination cursor from previous response',
                },
              },
              required: [],
            },
          },
          {
            name: 'search_rules',
            description:
              'Search firewall rules by target, action, status, or scope. Investigation use: find which rules already cover (or accidentally allow) a target before recommending changes.',
            inputSchema: {
              type: 'object',
              properties: {
                query: {
                  type: 'string',
                  description:
                    'Firewalla MSP rule query. Verified qualifiers: status:active|paused, action:allow|block|timelimit, box.id:UUID, box.group.id:GROUPID, device.id:"mac:AA:BB:CC:DD:EE:FF". Also commonly accepted: target.type:domain|ip|category|country|app, target.value:*.facebook.com, direction:bidirection|inbound|outbound, protocol:tcp|udp, scope.type:device|network|tag, notes:"text". Combine with spaces (implicit-AND grammar). Use - prefix to exclude. Examples: "action:block target.value:*.facebook.com", "status:paused", "target.type:category target.value:gamble", "action:block -status:paused".',
                },
              },
              required: [],
            },
          },
          {
            name: 'get_boxes',
            description:
              'List Firewalla boxes accessible to the MSP token. Returns each box\'s gid (UUID), name, model, online status, version, and group membership. No required parameters. Use this first when you need a box GID to pass to other tools.',
            inputSchema: {
              type: 'object',
              properties: {
                group: {
                  type: 'string',
                  description:
                    'Optional. Box group id — restricts results to boxes within one group. Group ids come from a prior get_boxes call (box.group.id).',
                },
              },
              required: [],
            },
          },
          {
            name: 'get_simple_statistics',
            description:
              'Top-level counts across the MSP account: online/offline box count, total alarms, total rules, total flows in the last 24h. No required parameters. Use as a one-shot health snapshot before drilling into other tools.',
            inputSchema: {
              type: 'object',
              properties: {
                group: {
                  type: 'string',
                  description:
                    'Optional. Box group id — scope the statistics to one group of boxes.',
                },
              },
              required: [],
            },
          },
          {
            name: 'get_statistics_by_region',
            description:
              'Top regions (ISO-3166 country codes) ranked by blocked-flow count. Useful for "where are blocked outbound flows headed?". No required parameters.',
            inputSchema: {
              type: 'object',
              properties: {
                group: {
                  type: 'string',
                  description:
                    'Optional. Box group id — scope statistics to one group.',
                },
                limit: {
                  type: 'number',
                  description:
                    'Optional. Maximum number of regions to return (default: 5).',
                  minimum: 1,
                  default: 5,
                },
              },
              required: [],
            },
          },
          {
            name: 'get_statistics_by_box',
            description:
              'Rank Firewalla boxes by one of two metrics: total blocked flows or total security alarms. Useful for "which box is taking the most heat?". No required parameters.',
            inputSchema: {
              type: 'object',
              properties: {
                type: {
                  type: 'string',
                  enum: ['topBoxesByBlockedFlows', 'topBoxesBySecurityAlarms'],
                  description:
                    'Optional. Metric to rank by (default: topBoxesByBlockedFlows). "topBoxesBySecurityAlarms" ranks by alarm count.',
                  default: 'topBoxesByBlockedFlows',
                },
                group: {
                  type: 'string',
                  description:
                    'Optional. Box group id — scope statistics to one group.',
                },
                limit: {
                  type: 'number',
                  description:
                    'Optional. Maximum number of boxes to return (default: 5).',
                  minimum: 1,
                  default: 5,
                },
              },
              required: [],
            },
          },
          {
            name: 'get_recent_flow_activity',
            description:
              'Get recent network flow activity snapshot (last 10-20 minutes). Returns up to 50 most recent flows for immediate analysis. CRITICAL: This is a quick snapshot tool only. Use this for: "what\'s happening right now?", current security threats, immediate network issues. DO NOT use for: historical analysis (use search_flows), getting more than 50 flows (use search_flows with limit), daily/weekly patterns (use search_flows with time queries like "ts:>24h"). For comprehensive analysis, always prefer search_flows.',
            inputSchema: {
              type: 'object',
              properties: {},
              required: [],
            },
          },
          {
            name: 'get_flow_insights',
            description:
              'Get category-based flow analysis including top content categories, bandwidth consumers, and blocked traffic. Ideal for answering questions like "what porn sites were accessed" or "what social media was used". Replaces time-based trends with actionable insights.',
            inputSchema: {
              type: 'object',
              properties: {
                period: {
                  type: 'string',
                  enum: ['1h', '24h', '7d', '30d'],
                  description: 'Time period for analysis (default: 24h)',
                  default: '24h',
                },
                categories: {
                  type: 'array',
                  items: {
                    type: 'string',
                    enum: [
                      'ad',
                      'edu',
                      'games',
                      'gamble',
                      'intel',
                      'p2p',
                      'porn',
                      'private',
                      'social',
                      'shopping',
                      'video',
                      'vpn',
                    ],
                  },
                  description:
                    'Filter to specific content categories (optional)',
                },
                include_blocked: {
                  type: 'boolean',
                  description:
                    'Include blocked traffic analysis (default: false)',
                  default: false,
                },
              },
              required: [],
            },
          },
          {
            name: 'get_alarm_trends',
            description:
              'Daily alarm volume time series for the last ~30 days (one bucket per day). Useful for spotting whether alarms are spiking or trailing off. No required parameters.',
            inputSchema: {
              type: 'object',
              properties: {
                group: {
                  type: 'string',
                  description:
                    'Optional. Box group id — scope trend to one group.',
                },
              },
              required: [],
            },
          },
          {
            name: 'get_rule_trends',
            description:
              'Daily count of new firewall rules created over the last ~30 days. Useful for change-management visibility. No required parameters.',
            inputSchema: {
              type: 'object',
              properties: {
                group: {
                  type: 'string',
                  description:
                    'Optional. Box group id — scope trend to one group.',
                },
              },
              required: [],
            },
          },
          // Convenience Wrappers (5 tools)
          {
            name: 'get_bandwidth_usage',
            description:
              'Top bandwidth-consuming devices for a time window, ranked by total bytes (download + upload). Required: period. For per-device flow detail behind the totals, follow up with investigate_device or search_flows scoped to the device id.',
            inputSchema: {
              type: 'object',
              properties: {
                period: {
                  type: 'string',
                  description:
                    'Required. Time window for the bandwidth roll-up. One of: "1h", "24h", "7d", "30d".',
                  enum: ['1h', '24h', '7d', '30d'],
                },
                limit: {
                  type: 'number',
                  description:
                    'Optional. Number of top devices to return (1-500, default: 10).',
                  minimum: 1,
                  maximum: 500,
                  default: 10,
                },
                box: {
                  type: 'string',
                  description:
                    'Optional. Box GID (UUID) — restrict to one Firewalla box. Get from get_boxes.',
                },
              },
              required: ['period'],
            },
          },
          {
            name: 'get_offline_devices',
            description:
              'List devices currently marked offline by Firewalla. No required parameters — defaults return the 100 most-recently-offline devices. Useful for "what hasn\'t checked in lately?".',
            inputSchema: {
              type: 'object',
              properties: {
                limit: {
                  type: 'number',
                  description:
                    'Optional. Maximum offline devices to return (1-500, default: 100).',
                  minimum: 1,
                  maximum: 500,
                  default: 100,
                },
                sort_by_last_seen: {
                  type: 'boolean',
                  description:
                    'Optional. When true (default), sort by last_seen descending (most-recently-online first). When false, default API ordering.',
                  default: true,
                },
                box: {
                  type: 'string',
                  description:
                    'Optional. Box GID (UUID) — restrict to one Firewalla box.',
                },
              },
              required: [],
            },
          },
          {
            name: 'search_devices',
            description:
              'Search devices with client-side filtering on the device inventory. Investigation use: locate a device by IP/MAC/name or list all offline-Apple devices, etc. For "tell me everything that happened with this device" prefer investigate_device.',
            inputSchema: {
              type: 'object',
              properties: {
                query: {
                  type: 'string',
                  description:
                    'Client-side device query. Supported fields: id (full device id including mac: prefix), name:*iPhone*, ip:192.168.1.*, mac:AA:BB:* (matches the device id portion after the mac: prefix), online:true|false, mac_vendor:Apple (alias: vendor), last_seen, total_download, total_upload, network.name:..., group.name:.... Combine with spaces (implicit-AND grammar). Examples: "online:false mac_vendor:Apple", "ip:192.168.1.* name:*laptop*", "online:true group.name:*kids*", "online:true -mac_vendor:Apple".',
                },
                status: {
                  type: 'string',
                  enum: ['online', 'offline', 'any'],
                  default: 'any',
                  description: 'Filter by online status',
                },
                limit: {
                  type: 'number',
                  minimum: 1,
                  maximum: 500,
                  default: 50,
                  description: 'Maximum number of devices to return',
                },
                box: {
                  type: 'string',
                  description: 'Filter devices under a specific Firewalla box',
                },
              },
              required: [],
            },
          },
          {
            name: 'search_target_lists',
            description:
              'Search target lists with client-side filtering (convenience wrapper around get_target_lists)',
            inputSchema: {
              type: 'object',
              properties: {
                query: {
                  type: 'string',
                  description:
                    'Client-side target-list query. Supported fields: name:*Social*, owner:global|<box_gid>, category:social|games|ad|porn|... (see firewalla://reference/categories), targets:*.facebook.com, notes:"description text". Combine with spaces (implicit-AND grammar). Examples: "category:social", "owner:global name:*Block*", "targets:*.gaming.com", "category:social -owner:global".',
                },
                category: {
                  type: 'string',
                  description: 'Filter by category',
                },
                owner: {
                  type: 'string',
                  description: 'Filter by owner (global or box gid)',
                },
                limit: {
                  type: 'number',
                  minimum: 1,
                  maximum: 500,
                  default: 100,
                  description: 'Maximum number of target lists to return',
                },
              },
              required: [],
            },
          },
          {
            name: 'get_network_rules_summary',
            description:
              'High-level rollup of firewall rules: total count, counts by action (allow / block / timelimit), counts by target type (domain / category / ip / country / app), and active-vs-paused counts. No required parameters. Useful for "what does the firewall policy look like at a glance?" before drilling in with search_rules.',
            inputSchema: {
              type: 'object',
              properties: {
                active_only: {
                  type: 'boolean',
                  description:
                    'Optional. When true (default), only count rules with status:active. Set false to include paused rules.',
                  default: true,
                },
                rule_type: {
                  type: 'string',
                  description:
                    'Optional. Filter the rollup to a single action: "allow" | "block" | "timelimit".',
                },
              },
              required: [],
            },
          },
          // Investigation composite tools (4 tools) - one-call correlation
          // primitives designed for AI security investigation agents.
          {
            name: 'investigate_ip',
            description:
              'Investigation primitive: correlate everything touching a single IP. Returns the matching device record (if any), all flows where the IP is source/destination/device-IP, all alarms where device or remote IP matches, and any firewall rules whose target or scope references the IP - in one structured payload. Prefer this over chaining search_flows + search_alarms + search_rules + search_devices manually.',
            inputSchema: {
              type: 'object',
              properties: {
                ip: {
                  type: 'string',
                  description:
                    'IPv4 or IPv6 address to investigate (required).',
                },
                lookback_hours: {
                  type: 'number',
                  description:
                    'Lookback window in hours (default: 24, max: 720).',
                  minimum: 1,
                  maximum: 720,
                  default: 24,
                },
              },
              required: ['ip'],
            },
          },
          {
            name: 'investigate_device',
            description:
              'Investigation primitive: one-call dossier for a device. Resolves the device by full id ("mac:AA:BB:CC:DD:EE:FF"), bare MAC, or current IP and returns the device record, alarms touching it, recent flows, a bandwidth + peer + region + category summary, and firewall rules scoped to it.',
            inputSchema: {
              type: 'object',
              properties: {
                device: {
                  type: 'string',
                  description:
                    'Device identifier (required). Accepts full id ("mac:AA:BB:CC:DD:EE:FF" / "wg_peer:..." / "ovpn:..."), bare MAC, or the device current IP.',
                },
                lookback_hours: {
                  type: 'number',
                  description:
                    'Lookback window in hours (default: 24, max: 720).',
                  minimum: 1,
                  maximum: 720,
                  default: 24,
                },
              },
              required: ['device'],
            },
          },
          {
            name: 'get_alarm_context',
            description:
              'Investigation primitive: fetch an alarm and group related alarms by same device, same remote IP, same remote domain, and same alarm type within a +/- time window. Useful for "is this a one-off or part of a wave?".',
            inputSchema: {
              type: 'object',
              properties: {
                alarm_id: {
                  type: 'string',
                  description: 'Alarm id (aid) to anchor on (required).',
                },
                box: {
                  type: 'string',
                  description:
                    'Box GID (optional; defaults to FIREWALLA_BOX_ID).',
                },
                window_seconds: {
                  type: 'number',
                  description:
                    'Half-width of the time window in seconds (default: 21600 = 6 hours; max: 604800 = 7 days).',
                  minimum: 60,
                  maximum: 604800,
                  default: 21600,
                },
              },
              required: ['alarm_id'],
            },
          },
          {
            name: 'get_target_timeline',
            description:
              'Investigation primitive: build a chronological timeline of events for a target (IPv4/IPv6, domain, or device id). Each entry has a `kind` discriminator ("alarm" | "flow" | "rule"). Use for narrative reconstruction across signal types.',
            inputSchema: {
              type: 'object',
              properties: {
                target: {
                  type: 'string',
                  description:
                    'Target identifier (required). IPv4/IPv6 address, domain (e.g. example.com), or device id (mac:AA:BB:...).',
                },
                lookback_hours: {
                  type: 'number',
                  description:
                    'Lookback window in hours (default: 24, max: 720).',
                  minimum: 1,
                  maximum: 720,
                  default: 24,
                },
              },
              required: ['target'],
            },
          },
          // Report composite tools (5 tools) - agent-callable equivalents of
          // the corresponding MCP prompts. Each returns { data, narrative }.
          {
            name: 'generate_security_report',
            description:
              'Compose a structured Firewalla security report (status + metrics + active alarms + recent threats) over the chosen window. No required parameters. Returns { data, narrative } where narrative matches the security_report MCP prompt output. Use this for a human-readable executive summary; for raw alarm pulls use get_active_alarms / search_alarms.',
            inputSchema: {
              type: 'object',
              properties: {
                period: {
                  type: 'string',
                  enum: ['24h', '7d', '30d'],
                  description:
                    'Optional. Lookback window (default: "24h"). One of: "24h", "7d", "30d".',
                  default: '24h',
                },
              },
              required: [],
            },
          },
          {
            name: 'generate_threat_analysis',
            description:
              'Run a threat-pattern analysis correlating active alarms, recent threats, and current rule coverage. No required parameters. Returns { data, narrative }. Use after generate_security_report when you want a deeper "what threats are recurring?" view.',
            inputSchema: {
              type: 'object',
              properties: {
                severity_threshold: {
                  type: 'string',
                  enum: ['low', 'medium', 'high', 'critical'],
                  description:
                    'Optional. Drop signals below this severity (default: "medium"). One of: "low" | "medium" | "high" | "critical".',
                  default: 'medium',
                },
              },
              required: [],
            },
          },
          {
            name: 'generate_bandwidth_analysis_report',
            description:
              'Compose a bandwidth-analysis report: top consumers, heavy-user counts, period totals. Required: period. Returns { data, narrative }.',
            inputSchema: {
              type: 'object',
              properties: {
                period: {
                  type: 'string',
                  enum: ['1h', '24h', '7d', '30d'],
                  description:
                    'Required. Lookback window. One of: "1h" | "24h" | "7d" | "30d".',
                },
                threshold_mb: {
                  type: 'number',
                  description:
                    'Optional. "Heavy user" threshold in megabytes (default: 100). Devices whose total transfer exceeds this in the window are counted as heavy users.',
                  minimum: 1,
                  default: 100,
                },
              },
              required: ['period'],
            },
          },
          {
            name: 'generate_device_investigation_report',
            description:
              'Compose a device-investigation report with narrative summary. Required: device_id. Returns { data, narrative }. For raw correlated data without the narrative, prefer investigate_device.',
            inputSchema: {
              type: 'object',
              properties: {
                device_id: {
                  type: 'string',
                  description:
                    'Required. Full device id (preferred format "mac:AA:BB:CC:DD:EE:FF"; also accepts "wg_peer:..." and "ovpn:..."). Source from get_device_status, search_devices, or alarm.device.id.',
                },
                lookback_hours: {
                  type: 'number',
                  description:
                    'Optional. Lookback window in hours (1-720, default: 24).',
                  minimum: 1,
                  maximum: 720,
                  default: 24,
                },
              },
              required: ['device_id'],
            },
          },
          {
            name: 'generate_network_health_report',
            description:
              'Compose a holistic network-health report (performance + security + overall health scores, plus contributing signals). No required parameters. Returns { data, narrative }.',
            inputSchema: {
              type: 'object',
              properties: {},
              required: [],
            },
          },
        ],
      };
    });

    // Set up tool handlers using the registry
    setupTools(targetServer, this.firewalla);

    // Set up resources
    setupResources(targetServer, this.firewalla);

    // Set up prompts
    setupPrompts(targetServer, this.firewalla);
  }

  /**
   * Starts the MCP server using configured transport (stdio or HTTP)
   */
  async start(): Promise<void> {
    const transportType = config.transport.type;

    if (transportType === 'stdio') {
      await this.startStdioTransport();
    } else if (transportType === 'http') {
      await this.startHttpTransport();
    }
    // Note: TypeScript type system ensures transportType is 'stdio' | 'http'
    // No else block needed - config validation ensures only valid values reach here
  }

  /**
   * Starts the MCP server using stdio transport
   */
  private async startStdioTransport(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    logger.info(
      'Firewalla MCP Server running with 37 tools on stdio transport'
    );
  }

  /**
   * Starts the MCP server using HTTP transport with StreamableHTTP.
   *
   * Hardening applied here (vs. a default MCP HTTP setup):
   *  - Binds to `config.transport.host` (default 127.0.0.1) so the listener
   *    does NOT default to 0.0.0.0 (every interface).
   *  - Validates the `Host` header against an allowlist to mitigate DNS
   *    rebinding attacks from browsers on the same machine.
   *  - Validates the `Origin` header against an allowlist when configured;
   *    when the allowlist is empty, only requests with no Origin header
   *    (curl/Postman/MCP CLI clients) are accepted.
   *  - Optionally enforces an `Authorization: Bearer <token>` header when
   *    `MCP_HTTP_BEARER` is set, compared with `timingSafeEqual`.
   *  - Adds defensive security headers via `SecurityManager.createSecureHeaders`
   *    to every response.
   *  - Constructs a fresh `Server` instance per session, so cross-session
   *    response routing (GHSA-345p-7cg4-v4c7) cannot occur even if a future
   *    SDK regression reintroduces the shared-server class of bug.
   *  - Pre-checks `Content-Length` and applies a 30s request timeout to bound
   *    slow-loris style attacks against the body parser.
   *  - Also configures the SDK-side `enableDnsRebindingProtection` /
   *    `allowedHosts` / `allowedOrigins` knobs as defense in depth (still
   *    available in SDK 1.29 albeit marked deprecated in favor of middleware
   *    — we do both).
   */
  private async startHttpTransport(): Promise<void> {
    const {
      port,
      path,
      host,
      allowedHosts,
      allowedOrigins,
      bearerToken,
    } = config.transport;

    const securityHeaders = this.security.createSecureHeaders();

    // Map to store transports by session ID. We also keep the per-session
    // Server alongside the transport so it can be torn down together.
    interface Session {
      transport: StreamableHTTPServerTransport;
      server: Server;
    }
    const sessions = new Map<string, Session>();

    // Helper to apply security headers + JSON content-type to a response.
    const writeJsonResponse = (
      res: ServerResponse,
      status: number,
      payload: unknown
    ): void => {
      res.writeHead(status, {
        'Content-Type': 'application/json',
        ...securityHeaders,
      });
      res.end(JSON.stringify(payload));
    };

    // Compare two strings in constant time. Returns false on length mismatch
    // without leaking via timing.
    const safeCompare = (a: string, b: string): boolean => {
      const ab = Buffer.from(a);
      const bb = Buffer.from(b);
      if (ab.length !== bb.length) {
        return false;
      }
      return timingSafeEqual(ab, bb);
    };

    // Returns null if the request is allowed, otherwise an HTTP status + a
    // JSON-RPC error payload to send back. This is the SECURITY GATE for the
    // HTTP transport; called before any body is read.
    const checkAuthorization = (
      req: IncomingMessage
    ): { status: number; payload: unknown } | null => {
      // Host header validation — defends against DNS rebinding.
      const hostHeader = req.headers.host;
      if (!hostHeader || !allowedHosts.includes(hostHeader)) {
        logger.warn('HTTP request rejected: Host header not in allowlist', {
          host_header: hostHeader,
          allowed_hosts: allowedHosts,
        });
        return {
          status: 403,
          payload: {
            jsonrpc: '2.0',
            error: { code: -32000, message: 'Forbidden host' },
            id: null,
          },
        };
      }

      // Origin header validation. When the operator hasn't configured an
      // origin allowlist, requests with NO Origin header are allowed (the
      // common case for CLI MCP clients) but any cross-origin browser request
      // is rejected — the browser always sends Origin for cross-origin fetches.
      const originHeader = req.headers.origin;
      if (originHeader !== undefined) {
        if (allowedOrigins.length === 0) {
          logger.warn(
            'HTTP request rejected: Origin header present but no allowlist configured',
            { origin: originHeader }
          );
          return {
            status: 403,
            payload: {
              jsonrpc: '2.0',
              error: { code: -32000, message: 'Forbidden origin' },
              id: null,
            },
          };
        }
        if (!allowedOrigins.includes(originHeader)) {
          logger.warn('HTTP request rejected: Origin header not in allowlist', {
            origin: originHeader,
          });
          return {
            status: 403,
            payload: {
              jsonrpc: '2.0',
              error: { code: -32000, message: 'Forbidden origin' },
              id: null,
            },
          };
        }
      }

      // Optional bearer token. Activated only when MCP_HTTP_BEARER is set;
      // otherwise the transport relies on Host/Origin checks + loopback bind.
      if (bearerToken) {
        const authHeader = req.headers.authorization;
        const expected = `Bearer ${bearerToken}`;
        if (!authHeader || !safeCompare(authHeader, expected)) {
          return {
            status: 401,
            payload: {
              jsonrpc: '2.0',
              error: { code: -32000, message: 'Unauthorized' },
              id: null,
            },
          };
        }
      }

      return null;
    };

    // Read JSON body with a strict size cap, a Content-Length precheck (so we
    // don't even start reading a 100MB body), and a 30s timeout (so a slow
    // sender can't pin a socket open holding a body parser hostage).
    const parseJsonBody = async (req: IncomingMessage): Promise<unknown> => {
      const MAX_BODY_SIZE = 1024 * 1024; // 1 MiB
      const REQUEST_TIMEOUT_MS = 30_000;

      // Parse Content-Length strictly: parseInt accepts trailing junk
      // ('1abc' -> 1) and hex prefixes, which would defeat the precheck.
      // The streaming guard below still enforces the cap byte-by-byte;
      // this is defense in depth.
      const clRaw = req.headers['content-length'];
      const declaredLen = clRaw !== undefined && /^\d+$/.test(clRaw)
        ? Number(clRaw)
        : 0;
      if (declaredLen > MAX_BODY_SIZE) {
        req.destroy();
        throw new Error('Request body too large (max 1MB)');
      }

      return new Promise((resolve, reject) => {
        let body = '';
        let size = 0;
        let settled = false;
        const settle = (fn: () => void): void => {
          if (settled) {return;}
          settled = true;
          fn();
        };

        const timer = setTimeout(() => {
          req.destroy();
          settle(() =>
            reject(new Error('Request body read timed out after 30s'))
          );
        }, REQUEST_TIMEOUT_MS);

        req.on('data', chunk => {
          size += chunk.length;
          if (size > MAX_BODY_SIZE) {
            clearTimeout(timer);
            req.destroy();
            settle(() =>
              reject(new Error('Request body too large (max 1MB)'))
            );
            return;
          }
          body += chunk.toString();
        });
        req.on('end', () => {
          clearTimeout(timer);
          try {
            settle(() => resolve(body ? JSON.parse(body) : null));
          } catch (_error) {
            settle(() => reject(new Error('Invalid JSON in request body')));
          }
        });
        req.on('error', err => {
          clearTimeout(timer);
          settle(() => reject(err));
        });
      });
    };

    // Construct the per-request HTTP handler. Captures `this` via the
    // outer-arrow so it can call setupHandlers / createServerInstance.
    const requestHandler = (req: IncomingMessage, res: ServerResponse) => {
      void (async () => {
        // Path gate first — anything outside our configured /mcp prefix gets
        // 404 without even surfacing in security logs.
        if (!req.url?.startsWith(path)) {
          writeJsonResponse(res, 404, { error: 'Not found' });
          return;
        }

        // Security gate: Host / Origin / Bearer. Runs BEFORE body parsing.
        const rejection = checkAuthorization(req);
        if (rejection) {
          writeJsonResponse(res, rejection.status, rejection.payload);
          return;
        }

        const sessionId = req.headers['mcp-session-id'] as string | undefined;

        // Validate session ID format if present
        if (sessionId && !isValidUUID(sessionId)) {
          writeJsonResponse(res, 400, {
            jsonrpc: '2.0',
            error: {
              code: -32000,
              message: 'Invalid session ID format (must be UUID v4)',
            },
            id: null,
          });
          return;
        }

        try {
          if (req.method === 'POST') {
            // Handle POST requests for MCP messages
            const parsedBody = await parseJsonBody(req);

            let transport: StreamableHTTPServerTransport;

            if (sessionId && sessions.has(sessionId)) {
              // Reuse existing transport for this session
              ({ transport } = sessions.get(sessionId)!);
            } else if (!sessionId && isInitializeRequest(parsedBody)) {
              // New initialization request — create new transport AND a
              // fresh Server instance scoped to this session. The fresh
              // Server is the structural fix for GHSA-345p-7cg4-v4c7
              // (cross-client data leak via shared server/transport).
              const newSessionId = randomUUID();
              transport = new StreamableHTTPServerTransport({
                sessionIdGenerator: () => newSessionId,
                enableDnsRebindingProtection: true,
                allowedHosts,
                allowedOrigins:
                  allowedOrigins.length > 0 ? allowedOrigins : undefined,
                onsessioninitialized: (initializedSessionId: string) => {
                  logger.info(
                    `HTTP session initialized: ${initializedSessionId}`
                  );
                },
              });

              const sessionServer = this.createServerInstance();
              this.setupHandlers(sessionServer);

              // Store session before connect to avoid the well-known race
              // between connect()-time message arrival and map population.
              sessions.set(newSessionId, {
                transport,
                server: sessionServer,
              });

              // Tear down both the transport and the per-session Server
              // when the client disconnects.
              transport.onclose = () => {
                const sid = transport.sessionId;
                if (sid && sessions.has(sid)) {
                  const sess = sessions.get(sid)!;
                  logger.info(`HTTP session closed: ${sid}`);
                  sessions.delete(sid);
                  // best-effort: detach server. Server.close() exists in
                  // SDK; ignore errors since the transport is already going.
                  sess.server.close().catch(() => {
                    /* deliberately ignored */
                  });
                }
              };

              await sessionServer.connect(transport);
            } else {
              writeJsonResponse(res, 400, {
                jsonrpc: '2.0',
                error: {
                  code: -32000,
                  message: 'Bad Request: No valid session ID provided',
                },
                id: null,
              });
              return;
            }

            // Apply security headers to the eventual response. Note: the
            // SDK transport writes its own response headers; we set ours
            // first via writeHead earlier paths; for the streaming path
            // we set them on a wrapped response below.
            for (const [k, v] of Object.entries(securityHeaders)) {
              res.setHeader(k, v);
            }

            await transport.handleRequest(req, res, parsedBody);
          } else if (req.method === 'GET') {
            // SSE stream — must have a known session.
            if (!sessionId || !sessions.has(sessionId)) {
              writeJsonResponse(res, 400, {
                jsonrpc: '2.0',
                error: {
                  code: -32000,
                  message: 'Invalid or missing session ID',
                },
                id: null,
              });
              return;
            }
            for (const [k, v] of Object.entries(securityHeaders)) {
              res.setHeader(k, v);
            }
            const { transport } = sessions.get(sessionId)!;
            await transport.handleRequest(req, res);
          } else if (req.method === 'DELETE') {
            if (!sessionId || !sessions.has(sessionId)) {
              writeJsonResponse(res, 400, {
                jsonrpc: '2.0',
                error: {
                  code: -32000,
                  message: 'Invalid or missing session ID',
                },
                id: null,
              });
              return;
            }
            for (const [k, v] of Object.entries(securityHeaders)) {
              res.setHeader(k, v);
            }
            const { transport } = sessions.get(sessionId)!;
            await transport.handleRequest(req, res);
          } else {
            res.writeHead(405, {
              'Content-Type': 'text/plain',
              ...securityHeaders,
            });
            res.end('Method Not Allowed');
          }
        } catch (error) {
          logger.error(
            'Error handling HTTP request:',
            error instanceof Error ? error : new Error(String(error))
          );
          if (!res.headersSent) {
            writeJsonResponse(res, 500, {
              jsonrpc: '2.0',
              error: {
                code: -32603,
                message: 'Internal server error',
              },
              id: null,
            });
          }
        }
      })();
    };

    const httpServer = createServer(requestHandler);

    // Start listening with error handling. Binding to `host` (default
    // 127.0.0.1) is the difference between exposing this server to LAN
    // neighbors vs. only the local machine.
    await new Promise<void>((resolve, reject) => {
      httpServer.on('error', err => {
        logger.error(
          'HTTP server error (port conflict or permission issue):',
          err instanceof Error ? err : new Error(String(err))
        );
        reject(err);
      });

      httpServer.listen(port, host, () => {
        logger.info(
          `Firewalla MCP Server running with 37 tools on HTTP transport`
        );
        logger.info(
          `HTTP server listening on http://${host}:${port}${path} ` +
            `(allowedHosts=${allowedHosts.length}, allowedOrigins=${allowedOrigins.length}, ` +
            `bearerAuth=${bearerToken ? 'on' : 'off'})`
        );
        resolve();
      });
    });

    // Handle graceful shutdown
    let isShuttingDown = false;
    const shutdown = () => {
      // Prevent duplicate shutdown sequences
      if (isShuttingDown) {
        logger.warn('Shutdown already in progress, ignoring signal');
        return;
      }
      isShuttingDown = true;

      void (async () => {
        logger.info('Shutting down HTTP server...');

        // Close all active sessions — transport AND the per-session Server.
        for (const [sessionId, sess] of sessions.entries()) {
          try {
            await sess.transport.close();
            await sess.server.close();
            sessions.delete(sessionId);
          } catch (error) {
            logger.error(
              `Error closing session ${sessionId}:`,
              error instanceof Error ? error : new Error(String(error))
            );
          }
        }

        // Close HTTP server with error handling and timeout
        const shutdownTimeout = setTimeout(() => {
          logger.error('HTTP server shutdown timed out, forcing exit');
          process.exit(1);
        }, 10000); // 10 second timeout

        httpServer.close(err => {
          clearTimeout(shutdownTimeout);
          if (err) {
            logger.error(
              'Error during HTTP server shutdown:',
              err instanceof Error ? err : new Error(String(err))
            );
            process.exit(1);
          } else {
            logger.info('HTTP server shut down complete');
            process.exit(0);
          }
        });
      })();
    };

    // Track signal handler registration to prevent duplicates
    if (!FirewallaMCPServer.signalHandlersRegistered) {
      process.on('SIGINT', shutdown);
      process.on('SIGTERM', shutdown);
      FirewallaMCPServer.signalHandlersRegistered = true;
    }
  }
}

// Start the server if this file is run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  const server = new FirewallaMCPServer();
  server.start().catch((error: unknown) => {
    logger.error(
      'Failed to start server:',
      error instanceof Error ? error : new Error(String(error))
    );
    process.exit(1);
  });
}
