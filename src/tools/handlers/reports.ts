/**
 * @fileoverview Agent-callable tools that wrap the shared report builders.
 *
 * These tools expose the same composed context the MCP prompts have always
 * provided, but as structured JSON tool results so a downstream AI agent can
 * call them as part of an investigation flow. Each handler delegates to the
 * matching builder in `src/reports/` and returns both:
 *
 *   - `data`: machine-friendly structured payload.
 *   - `narrative`: the markdown report (identical to the prompt user-message
 *     text), useful when the agent wants to summarize for a human.
 */

import { BaseToolHandler, type ToolArgs, type ToolResponse } from './base.js';
import type { FirewallaClient } from '../../firewalla/client.js';
import { ErrorType } from '../../validation/error-handler.js';
import {
  buildSecurityReport,
  buildThreatAnalysis,
  buildBandwidthAnalysis,
  buildDeviceInvestigationReport,
  buildNetworkHealthReport,
} from '../../reports/index.js';

function asMessage(err: unknown): string {
  return err instanceof Error ? err.message : 'Unknown error';
}

export class GenerateSecurityReportHandler extends BaseToolHandler {
  name = 'generate_security_report';
  description =
    'Compose a structured Firewalla security report (firewall status + security metrics + active alarms + recent threats). Returns both a `data` JSON payload and a `narrative` markdown string identical to the security_report prompt output.';
  category = 'analytics' as const;

  constructor() {
    super({
      enableGeoEnrichment: false,
      enableFieldNormalization: false,
      additionalMeta: { data_source: 'security_report' },
    });
  }

  async execute(
    args: ToolArgs,
    firewalla: FirewallaClient
  ): Promise<ToolResponse> {
    try {
      const period = (args.period as string) || '24h';
      const report = await buildSecurityReport(firewalla, { period });
      return this.createUnifiedResponse(report);
    } catch (error) {
      return this.createErrorResponse(
        `Failed to generate security report: ${asMessage(error)}`,
        ErrorType.API_ERROR
      );
    }
  }
}

export class GenerateThreatAnalysisHandler extends BaseToolHandler {
  name = 'generate_threat_analysis';
  description =
    'Run a threat-pattern analysis (alarms + recent threats + current rule status) and return both a `data` JSON payload and a `narrative` markdown report.';
  category = 'analytics' as const;

  constructor() {
    super({
      enableGeoEnrichment: false,
      enableFieldNormalization: false,
      additionalMeta: { data_source: 'threat_analysis' },
    });
  }

  async execute(
    args: ToolArgs,
    firewalla: FirewallaClient
  ): Promise<ToolResponse> {
    try {
      const severityThreshold = (args.severity_threshold as string) || 'medium';
      const report = await buildThreatAnalysis(firewalla, {
        severityThreshold,
      });
      return this.createUnifiedResponse(report);
    } catch (error) {
      return this.createErrorResponse(
        `Failed to generate threat analysis: ${asMessage(error)}`,
        ErrorType.API_ERROR
      );
    }
  }
}

export class GenerateBandwidthAnalysisHandler extends BaseToolHandler {
  name = 'generate_bandwidth_analysis_report';
  description =
    'Compose a bandwidth-analysis report (top consumers + flow patterns + device status). Returns `data` JSON and a `narrative` markdown report. Requires `period`.';
  category = 'analytics' as const;

  constructor() {
    super({
      enableGeoEnrichment: false,
      enableFieldNormalization: false,
      additionalMeta: { data_source: 'bandwidth_analysis' },
    });
  }

  async execute(
    args: ToolArgs,
    firewalla: FirewallaClient
  ): Promise<ToolResponse> {
    try {
      const period = args.period as string;
      if (!period) {
        return this.createErrorResponse(
          'Parameter `period` is required (1h | 24h | 7d | 30d).',
          ErrorType.VALIDATION_ERROR
        );
      }
      const thresholdMb =
        typeof args.threshold_mb === 'number' ? args.threshold_mb : 100;
      const report = await buildBandwidthAnalysis(firewalla, {
        period,
        thresholdMb,
      });
      return this.createUnifiedResponse(report);
    } catch (error) {
      return this.createErrorResponse(
        `Failed to generate bandwidth analysis: ${asMessage(error)}`,
        ErrorType.API_ERROR
      );
    }
  }
}

export class GenerateDeviceInvestigationReportHandler extends BaseToolHandler {
  name = 'generate_device_investigation_report';
  description =
    'Compose a focused device-investigation report (device record + flow stats + alarms + connection patterns). Returns `data` JSON and a `narrative` markdown report. Requires `device_id`. For raw correlation without the narrative, use investigate_device.';
  category = 'analytics' as const;

  constructor() {
    super({
      enableGeoEnrichment: false,
      enableFieldNormalization: false,
      additionalMeta: { data_source: 'device_investigation' },
    });
  }

  async execute(
    args: ToolArgs,
    firewalla: FirewallaClient
  ): Promise<ToolResponse> {
    try {
      const deviceId = args.device_id as string;
      if (!deviceId) {
        return this.createErrorResponse(
          'Parameter `device_id` is required.',
          ErrorType.VALIDATION_ERROR
        );
      }
      const lookbackHours =
        typeof args.lookback_hours === 'number' ? args.lookback_hours : 24;
      const report = await buildDeviceInvestigationReport(firewalla, {
        deviceId,
        lookbackHours,
      });
      return this.createUnifiedResponse(report);
    } catch (error) {
      return this.createErrorResponse(
        `Failed to generate device investigation report: ${asMessage(error)}`,
        ErrorType.API_ERROR
      );
    }
  }
}

export class GenerateNetworkHealthReportHandler extends BaseToolHandler {
  name = 'generate_network_health_report';
  description =
    'Compose a holistic network-health report (system + devices + topology + security + rules + health scores). Returns `data` JSON and a `narrative` markdown report.';
  category = 'analytics' as const;

  constructor() {
    super({
      enableGeoEnrichment: false,
      enableFieldNormalization: false,
      additionalMeta: { data_source: 'network_health_check' },
    });
  }

  async execute(
    _args: ToolArgs,
    firewalla: FirewallaClient
  ): Promise<ToolResponse> {
    try {
      const report = await buildNetworkHealthReport(firewalla);
      return this.createUnifiedResponse(report);
    } catch (error) {
      return this.createErrorResponse(
        `Failed to generate network health report: ${asMessage(error)}`,
        ErrorType.API_ERROR
      );
    }
  }
}
