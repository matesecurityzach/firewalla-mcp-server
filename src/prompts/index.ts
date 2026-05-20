import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  GetPromptRequestSchema,
  ListPromptsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import type { FirewallaClient } from '../firewalla/client.js';
import {
  buildSecurityReport,
  buildThreatAnalysis,
  buildBandwidthAnalysis,
  buildDeviceInvestigationReport,
  buildNetworkHealthReport,
} from '../reports/index.js';

/**
 * Catalog of prompts exposed by ListPrompts.
 *
 * Each entry mirrors a case in the GetPrompt handler below. Keep this list in
 * sync if you add or remove a prompt. For agent-callable equivalents that
 * return structured data instead of chat messages, see the generate_* tools.
 */
export const PROMPT_CATALOG: ReadonlyArray<{
  name: string;
  description: string;
  arguments: Array<{
    name: string;
    description: string;
    required?: boolean;
  }>;
}> = [
  {
    name: 'security_report',
    description:
      'Composes a comprehensive Firewalla security report (firewall status + security metrics + active alarms + recent threats) and asks the model to analyze it.',
    arguments: [
      {
        name: 'period',
        description: 'Lookback period: 24h | 7d | 30d (default: 24h).',
        required: false,
      },
    ],
  },
  {
    name: 'threat_analysis',
    description:
      'Surfaces threat patterns and asks the model to recommend defensive actions.',
    arguments: [
      {
        name: 'severity_threshold',
        description:
          'Minimum severity to include (low | medium | high | critical; default: medium).',
        required: false,
      },
    ],
  },
  {
    name: 'bandwidth_analysis',
    description:
      'Asks the model to analyze bandwidth consumption and identify anomalies.',
    arguments: [
      {
        name: 'period',
        description: 'Required. Time period: 1h | 24h | 7d | 30d.',
        required: true,
      },
      {
        name: 'threshold_mb',
        description:
          'Bandwidth threshold in MB above which devices are considered "heavy" (default: 100).',
        required: false,
      },
    ],
  },
  {
    name: 'device_investigation',
    description:
      'Pulls a focused dossier for one device (flows, alarms, behavior) and asks the model to assess risk.',
    arguments: [
      {
        name: 'device_id',
        description:
          'Required. Device id (mac:..., wg_peer:..., ovpn:..., or numeric id).',
        required: true,
      },
      {
        name: 'lookback_hours',
        description: 'Investigation lookback window in hours (default: 24).',
        required: false,
      },
    ],
  },
  {
    name: 'network_health_check',
    description:
      'Pulls a holistic snapshot (system, devices, topology, security, rules) and asks the model to evaluate network health.',
    arguments: [],
  },
];

/**
 * Registers ListPrompts + GetPrompt handlers on the MCP server.
 *
 * Each GetPrompt case is a thin adapter that calls the corresponding builder
 * in `src/reports/` and wraps the `narrative` field as a user message.
 *
 * For agent-callable equivalents that return the same `data` + `narrative`
 * payload as a tool result, see the generate_* handlers in
 * `src/tools/handlers/reports.ts`.
 */
export function setupPrompts(server: Server, firewalla: FirewallaClient): void {
  server.setRequestHandler(ListPromptsRequestSchema, async () => ({
    prompts: PROMPT_CATALOG.map(({ name, description, arguments: args }) => ({
      name,
      description,
      arguments: args,
    })),
  }));

  server.setRequestHandler(GetPromptRequestSchema, async request => {
    const { name, arguments: args } = request.params;

    try {
      let narrative: string;

      switch (name) {
        case 'security_report': {
          const { narrative: text } = await buildSecurityReport(firewalla, {
            period: (args?.period as string) || '24h',
          });
          narrative = text;
          break;
        }

        case 'threat_analysis': {
          const { narrative: text } = await buildThreatAnalysis(firewalla, {
            severityThreshold: (args?.severity_threshold as string) || 'medium',
          });
          narrative = text;
          break;
        }

        case 'bandwidth_analysis': {
          const period = args?.period as string;
          if (!period) {
            throw new Error(
              'Period parameter is required for bandwidth analysis'
            );
          }
          const { narrative: text } = await buildBandwidthAnalysis(firewalla, {
            period,
            thresholdMb:
              typeof args?.threshold_mb === 'number' ? args.threshold_mb : 100,
          });
          narrative = text;
          break;
        }

        case 'device_investigation': {
          const deviceId = args?.device_id as string;
          if (!deviceId) {
            throw new Error(
              'Device ID parameter is required for device investigation'
            );
          }
          const { narrative: text } = await buildDeviceInvestigationReport(
            firewalla,
            {
              deviceId,
              lookbackHours:
                typeof args?.lookback_hours === 'number'
                  ? args.lookback_hours
                  : 24,
            }
          );
          narrative = text;
          break;
        }

        case 'network_health_check': {
          const { narrative: text } = await buildNetworkHealthReport(firewalla);
          narrative = text;
          break;
        }

        default:
          throw new Error(`Unknown prompt: ${name}`);
      }

      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: narrative,
            },
          },
        ],
      };
    } catch (error: unknown) {
      const errorMessage =
        error instanceof Error ? error.message : 'Unknown error occurred';
      return {
        messages: [
          {
            role: 'user',
            content: {
              type: 'text',
              text: `Error generating prompt '${name}': ${errorMessage}`,
            },
          },
        ],
      };
    }
  });
}
