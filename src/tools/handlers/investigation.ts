/**
 * @fileoverview Investigation composite tool handlers.
 *
 * These tools fan out to multiple existing FirewallaClient calls (flows,
 * alarms, rules, devices) and assemble a correlated payload in a single
 * response. They exist for AI agents that need to investigate a target
 * without manually chaining 5+ search calls.
 *
 * Tools:
 * - investigate_ip:      everything touching an IP (flows, alarms, rules, device).
 * - investigate_device:  one device's full footprint (record, flows, alarms,
 *                        bandwidth summary, rules scoped to the device).
 * - get_alarm_context:   one alarm + related alarms (same device, same remote
 *                        IP/domain, same type within a configurable window).
 * - get_target_timeline: chronological event timeline for an IP/domain/device.
 */

import { BaseToolHandler, type ToolArgs, type ToolResponse } from './base.js';
import type { FirewallaClient } from '../../firewalla/client.js';
import {
  ParameterValidator,
  ErrorType,
} from '../../validation/error-handler.js';
import { unixToISOStringOrNow } from '../../utils/timestamp.js';
import type { Alarm, Flow, NetworkRule, Device } from '../../types.js';

const DEFAULT_LOOKBACK_HOURS = 24;
const MAX_LOOKBACK_HOURS = 24 * 30; // 30 days
const DEFAULT_PER_ENTITY_LIMIT = 200;
const ALARM_RELATED_WINDOW_SECONDS = 60 * 60 * 6; // +/- 6 hours by default

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

function clampLookbackHours(raw: unknown): number {
  if (typeof raw !== 'number' || !Number.isFinite(raw) || raw <= 0) {
    return DEFAULT_LOOKBACK_HOURS;
  }
  return Math.min(Math.floor(raw), MAX_LOOKBACK_HOURS);
}

function isIPv4(value: string): boolean {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value.trim());
}

function isMacFormatted(value: string): boolean {
  return /^(?:mac:)?[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$/.test(value.trim());
}

function asUnixTs(value: unknown): number {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value > 1e12 ? Math.floor(value / 1000) : value;
  }
  if (typeof value === 'string') {
    const parsed = Date.parse(value);
    if (!Number.isNaN(parsed)) {
      return Math.floor(parsed / 1000);
    }
    const numeric = Number(value);
    if (Number.isFinite(numeric)) {
      return numeric > 1e12 ? Math.floor(numeric / 1000) : numeric;
    }
  }
  return 0;
}

function flowMatchesIp(flow: Flow, ip: string): boolean {
  return (
    flow.device?.ip === ip ||
    flow.source?.ip === ip ||
    flow.destination?.ip === ip
  );
}

function alarmMatchesIp(alarm: Alarm, ip: string): boolean {
  return alarm.device?.ip === ip || alarm.remote?.ip === ip;
}

function ruleTargetsIp(rule: NetworkRule, ip: string): boolean {
  return (
    rule.target?.value === ip ||
    rule.scope?.value === ip ||
    (typeof rule.target?.value === 'string' && rule.target.value.includes(ip))
  );
}

/**
 * Shared lookback fetch: pull recent flows/alarms/rules + the device inventory
 * within the requested window. Used by all four investigation tools.
 */
async function fetchInvestigationContext(
  firewalla: FirewallaClient,
  lookbackHours: number,
  flowLimit = DEFAULT_PER_ENTITY_LIMIT,
  alarmLimit = DEFAULT_PER_ENTITY_LIMIT
): Promise<{
  windowStart: number;
  windowEnd: number;
  flows: Flow[];
  alarms: Alarm[];
  rules: NetworkRule[];
  devices: Device[];
}> {
  const windowEnd = nowSeconds();
  const windowStart = windowEnd - lookbackHours * 3600;
  const tsRange = `ts:${windowStart}-${windowEnd}`;

  const [flowsResp, alarmsResp, rulesResp, devicesResp] = await Promise.all([
    firewalla
      .getFlowData(tsRange, undefined, 'ts:desc', flowLimit)
      .catch(() => ({ count: 0, results: [] as Flow[] })),
    firewalla
      .getActiveAlarms(tsRange, undefined, 'ts:desc', alarmLimit)
      .catch(() => ({ count: 0, results: [] as Alarm[] })),
    firewalla
      .getNetworkRules(undefined, 500)
      .catch(() => ({ count: 0, results: [] as NetworkRule[] })),
    firewalla.getDeviceStatus(undefined, true, 1000).catch(() => ({
      count: 0,
      results: [] as Device[],
      next_cursor: undefined,
      total_count: 0,
      has_more: false,
    })),
  ]);

  return {
    windowStart,
    windowEnd,
    flows: flowsResp.results || [],
    alarms: alarmsResp.results || [],
    rules: rulesResp.results || [],
    devices: devicesResp.results || [],
  };
}

function summarizeBytes(flows: Flow[]): {
  download: number;
  upload: number;
  total: number;
  flowCount: number;
} {
  let download = 0;
  let upload = 0;
  for (const flow of flows) {
    download += flow.download || 0;
    upload += flow.upload || 0;
  }
  return {
    download,
    upload,
    total: download + upload,
    flowCount: flows.length,
  };
}

export class InvestigateIpHandler extends BaseToolHandler {
  name = 'investigate_ip';
  description =
    'Correlate everything touching a single IP: flows (where IP is source/destination/device), alarms (where device IP or remote IP matches), firewall rules whose target/scope matches the IP, and any matching device inventory record - all in one structured payload.';
  category = 'investigation' as const;

  constructor() {
    super({
      enableGeoEnrichment: true,
      enableFieldNormalization: true,
      additionalMeta: {
        data_source: 'investigation_ip',
        entity_type: 'investigation_bundle',
      },
    });
  }

  async execute(
    args: ToolArgs,
    firewalla: FirewallaClient
  ): Promise<ToolResponse> {
    try {
      const ipValidation = ParameterValidator.validateRequiredString(
        args.ip,
        'ip'
      );
      if (!ipValidation.isValid) {
        return this.createErrorResponse(
          'Parameter validation failed',
          ErrorType.VALIDATION_ERROR,
          undefined,
          ipValidation.errors
        );
      }
      const ip = (ipValidation.sanitizedValue as string).trim();
      if (!isIPv4(ip) && !/^[0-9a-fA-F:]+$/.test(ip)) {
        return this.createErrorResponse(
          `Parameter 'ip' must be an IPv4 or IPv6 address (got '${ip}')`,
          ErrorType.VALIDATION_ERROR
        );
      }

      const lookbackHours = clampLookbackHours(args.lookback_hours);
      const ctx = await fetchInvestigationContext(firewalla, lookbackHours);

      const flows = ctx.flows.filter(f => flowMatchesIp(f, ip));
      const alarms = ctx.alarms.filter(a => alarmMatchesIp(a, ip));
      const rules = ctx.rules.filter(r => ruleTargetsIp(r, ip));
      const device =
        ctx.devices.find(d => d.ip === ip) ||
        ctx.devices.find(d => d.ip && d.ip.includes(ip));

      const inbound = flows.filter(
        f => f.destination?.ip === ip || f.direction === 'inbound'
      );
      const outbound = flows.filter(
        f => f.source?.ip === ip || f.direction === 'outbound'
      );
      const blocked = flows.filter(f => f.block);

      const remotePeers = new Set<string>();
      for (const f of flows) {
        if (f.source?.ip && f.source.ip !== ip) {
          remotePeers.add(f.source.ip);
        }
        if (f.destination?.ip && f.destination.ip !== ip) {
          remotePeers.add(f.destination.ip);
        }
      }

      const regionCounts = new Map<string, number>();
      for (const f of flows) {
        if (f.region) {
          regionCounts.set(f.region, (regionCounts.get(f.region) || 0) + 1);
        }
      }
      const topRegions = Array.from(regionCounts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([region, count]) => ({ region, flow_count: count }));

      const payload = {
        target: { ip, kind: 'ip' as const },
        window: {
          start: new Date(ctx.windowStart * 1000).toISOString(),
          end: new Date(ctx.windowEnd * 1000).toISOString(),
          lookback_hours: lookbackHours,
        },
        device: device
          ? {
              id: device.id,
              name: device.name,
              ip: device.ip,
              mac_vendor: device.macVendor,
              online: device.online,
              last_seen: device.lastSeen,
              network: device.network,
              group: device.group,
            }
          : null,
        summary: {
          flow_count: flows.length,
          inbound_flow_count: inbound.length,
          outbound_flow_count: outbound.length,
          blocked_flow_count: blocked.length,
          alarm_count: alarms.length,
          matching_rule_count: rules.length,
          unique_remote_peers: remotePeers.size,
          bytes: summarizeBytes(flows),
          top_regions: topRegions,
        },
        alarms: alarms.slice(0, 50).map(a => ({
          aid: a.aid,
          gid: a.gid,
          type: a.type,
          status: a.status,
          message: a.message,
          timestamp: unixToISOStringOrNow(a.ts),
          device: a.device,
          remote: a.remote,
        })),
        flows: flows.slice(0, 100).map(f => ({
          timestamp: unixToISOStringOrNow(f.ts),
          protocol: f.protocol,
          direction: f.direction,
          blocked: f.block,
          download: f.download,
          upload: f.upload,
          duration: f.duration,
          source_ip: f.source?.ip,
          destination_ip: f.destination?.ip,
          destination_name: f.destination?.name,
          region: f.region,
          category: f.category,
          device: {
            id: f.device?.id,
            name: f.device?.name,
            ip: f.device?.ip,
          },
        })),
        rules: rules.slice(0, 50).map(r => ({
          id: r.id,
          action: r.action,
          status: r.status,
          direction: r.direction,
          target: r.target,
          scope: r.scope,
          notes: r.notes,
        })),
      };

      return this.createUnifiedResponse(payload);
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      return this.createErrorResponse(
        `Failed to investigate IP: ${msg}`,
        ErrorType.API_ERROR
      );
    }
  }
}

export class InvestigateDeviceHandler extends BaseToolHandler {
  name = 'investigate_device';
  description =
    'One-call dossier for a device. Accepts a device identifier (full id like "mac:AA:BB:...", a bare MAC, or an IP) and returns the device record, alarms touching it, recent flows, a bandwidth summary, and active firewall rules scoped to it.';
  category = 'investigation' as const;

  constructor() {
    super({
      enableGeoEnrichment: true,
      enableFieldNormalization: true,
      additionalMeta: {
        data_source: 'investigation_device',
        entity_type: 'investigation_bundle',
      },
    });
  }

  async execute(
    args: ToolArgs,
    firewalla: FirewallaClient
  ): Promise<ToolResponse> {
    try {
      const idValidation = ParameterValidator.validateRequiredString(
        args.device,
        'device'
      );
      if (!idValidation.isValid) {
        return this.createErrorResponse(
          'Parameter validation failed',
          ErrorType.VALIDATION_ERROR,
          undefined,
          idValidation.errors
        );
      }
      const rawDevice = (idValidation.sanitizedValue as string).trim();
      const lookbackHours = clampLookbackHours(args.lookback_hours);

      const ctx = await fetchInvestigationContext(firewalla, lookbackHours);

      // Resolve to a device record. We try id-exact, mac-suffix, and IP match.
      const normalizedMac = isMacFormatted(rawDevice)
        ? rawDevice.startsWith('mac:')
          ? rawDevice
          : `mac:${rawDevice}`
        : null;
      const looksLikeIp = isIPv4(rawDevice);

      const device =
        ctx.devices.find(d => d.id === rawDevice) ||
        (normalizedMac
          ? ctx.devices.find(d => d.id === normalizedMac)
          : undefined) ||
        (looksLikeIp ? ctx.devices.find(d => d.ip === rawDevice) : undefined) ||
        ctx.devices.find(
          d => d.mac && d.mac.toLowerCase() === rawDevice.toLowerCase()
        ) ||
        null;

      if (!device) {
        return this.createErrorResponse(
          `Device '${rawDevice}' was not found in the current device inventory (lookback ${lookbackHours}h).`,
          ErrorType.API_ERROR,
          {
            hint: 'Try one of: full device id ("mac:AA:BB:CC:DD:EE:FF"), bare MAC, or current device IP. Use get_device_status or search_devices to confirm.',
          }
        );
      }

      const deviceIp = device.ip;
      const flows = ctx.flows.filter(f => {
        if (!deviceIp) {
          return false;
        }
        return (
          f.device?.id === device.id ||
          f.device?.ip === deviceIp ||
          f.source?.ip === deviceIp ||
          f.destination?.ip === deviceIp
        );
      });
      const alarms = ctx.alarms.filter(a => {
        if (a.device?.id === device.id) {
          return true;
        }
        if (
          deviceIp &&
          (a.device?.ip === deviceIp || a.remote?.ip === deviceIp)
        ) {
          return true;
        }
        return false;
      });
      const rules = ctx.rules.filter(r => {
        if (!deviceIp) {
          return false;
        }
        return (
          (r.scope?.type === 'device' && r.scope?.value === device.id) ||
          (r.scope?.value && r.scope.value === deviceIp) ||
          (r.target?.value && r.target.value === deviceIp)
        );
      });

      const blocked = flows.filter(f => f.block);
      const outbound = flows.filter(
        f => f.direction === 'outbound' || f.source?.ip === deviceIp
      );
      const inbound = flows.filter(
        f => f.direction === 'inbound' || f.destination?.ip === deviceIp
      );

      const remotePeerCounts = new Map<string, number>();
      const regionCounts = new Map<string, number>();
      const categoryCounts = new Map<string, number>();
      for (const f of flows) {
        const peer =
          f.source?.ip === deviceIp ? f.destination?.ip : f.source?.ip;
        if (peer) {
          remotePeerCounts.set(peer, (remotePeerCounts.get(peer) || 0) + 1);
        }
        if (f.region) {
          regionCounts.set(f.region, (regionCounts.get(f.region) || 0) + 1);
        }
        if (f.category) {
          categoryCounts.set(
            f.category,
            (categoryCounts.get(f.category) || 0) + 1
          );
        }
      }

      const topPeers = Array.from(remotePeerCounts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([ip, count]) => ({ ip, flow_count: count }));
      const topRegions = Array.from(regionCounts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([region, count]) => ({ region, flow_count: count }));
      const topCategories = Array.from(categoryCounts.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([category, count]) => ({ category, flow_count: count }));

      const payload = {
        target: {
          device_id: device.id,
          name: device.name,
          ip: device.ip,
          kind: 'device' as const,
        },
        window: {
          start: new Date(ctx.windowStart * 1000).toISOString(),
          end: new Date(ctx.windowEnd * 1000).toISOString(),
          lookback_hours: lookbackHours,
        },
        device: {
          id: device.id,
          gid: device.gid,
          name: device.name,
          ip: device.ip,
          mac: device.mac,
          mac_vendor: device.macVendor,
          online: device.online,
          last_seen: device.lastSeen,
          network: device.network,
          group: device.group,
          total_download: device.totalDownload,
          total_upload: device.totalUpload,
        },
        summary: {
          flow_count: flows.length,
          inbound_flow_count: inbound.length,
          outbound_flow_count: outbound.length,
          blocked_flow_count: blocked.length,
          alarm_count: alarms.length,
          matching_rule_count: rules.length,
          bytes: summarizeBytes(flows),
          top_peers: topPeers,
          top_regions: topRegions,
          top_categories: topCategories,
        },
        alarms: alarms.slice(0, 50).map(a => ({
          aid: a.aid,
          gid: a.gid,
          type: a.type,
          status: a.status,
          message: a.message,
          timestamp: unixToISOStringOrNow(a.ts),
          device: a.device,
          remote: a.remote,
        })),
        recent_flows: flows.slice(0, 100).map(f => ({
          timestamp: unixToISOStringOrNow(f.ts),
          protocol: f.protocol,
          direction: f.direction,
          blocked: f.block,
          download: f.download,
          upload: f.upload,
          source_ip: f.source?.ip,
          destination_ip: f.destination?.ip,
          destination_name: f.destination?.name,
          region: f.region,
          category: f.category,
        })),
        rules: rules.slice(0, 50).map(r => ({
          id: r.id,
          action: r.action,
          status: r.status,
          direction: r.direction,
          target: r.target,
          scope: r.scope,
          notes: r.notes,
        })),
      };

      return this.createUnifiedResponse(payload);
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      return this.createErrorResponse(
        `Failed to investigate device: ${msg}`,
        ErrorType.API_ERROR
      );
    }
  }
}

export class GetAlarmContextHandler extends BaseToolHandler {
  name = 'get_alarm_context';
  description =
    'Fetch an alarm by id plus related alarms grouped by similarity: same device, same remote IP, same remote domain, and same alarm type within a configurable +/- time window. Useful for "is this a one-off or part of a wave?".';
  category = 'investigation' as const;

  constructor() {
    super({
      enableGeoEnrichment: true,
      enableFieldNormalization: true,
      additionalMeta: {
        data_source: 'investigation_alarm_context',
        entity_type: 'investigation_bundle',
      },
    });
  }

  async execute(
    args: ToolArgs,
    firewalla: FirewallaClient
  ): Promise<ToolResponse> {
    try {
      const idValidation = ParameterValidator.validateRequiredString(
        args.alarm_id,
        'alarm_id'
      );
      if (!idValidation.isValid) {
        return this.createErrorResponse(
          'Parameter validation failed',
          ErrorType.VALIDATION_ERROR,
          undefined,
          idValidation.errors
        );
      }

      const alarmId = (idValidation.sanitizedValue as string).trim();
      const windowSecondsRaw = args.window_seconds;
      const windowSeconds =
        typeof windowSecondsRaw === 'number' && windowSecondsRaw > 0
          ? Math.min(Math.floor(windowSecondsRaw), 60 * 60 * 24 * 7)
          : ALARM_RELATED_WINDOW_SECONDS;

      const gid = typeof args.box === 'string' ? args.box : undefined;
      const detail = await firewalla.getSpecificAlarm(alarmId, gid);
      const target = detail.results?.[0];
      if (!target) {
        return this.createErrorResponse(
          `Alarm '${alarmId}' not found.`,
          ErrorType.API_ERROR
        );
      }

      const targetTs = asUnixTs(target.ts);
      const tsLow = targetTs - windowSeconds;
      const tsHigh = targetTs + windowSeconds;

      const lookbackHours = Math.max(
        DEFAULT_LOOKBACK_HOURS,
        Math.ceil((windowSeconds * 2) / 3600)
      );
      const ctx = await fetchInvestigationContext(
        firewalla,
        lookbackHours,
        0,
        DEFAULT_PER_ENTITY_LIMIT
      );

      const sameDevice = ctx.alarms.filter(
        a =>
          target.device?.id &&
          a.device?.id === target.device.id &&
          a.aid !== target.aid
      );
      const sameRemoteIp = ctx.alarms.filter(
        a =>
          target.remote?.ip &&
          a.remote?.ip === target.remote.ip &&
          a.aid !== target.aid
      );
      // Alarms don't have a guaranteed `remote.domain` field — the verified
      // Firewalla MSP schema only exposes `remote.{id, name, ip, geo}` for
      // alarms. Use `remote.name` (typically the hostname / domain literal)
      // and any optional `remote.domain` that the API may have started
      // returning. Either match counts.
      const targetDomain =
        (target.remote as { domain?: string } | undefined)?.domain ||
        target.remote?.name;
      const sameRemoteDomain = targetDomain
        ? ctx.alarms.filter(a => {
            if (a.aid === target.aid) {
              return false;
            }
            const aDomain =
              (a.remote as { domain?: string } | undefined)?.domain ||
              a.remote?.name;
            return aDomain === targetDomain;
          })
        : [];
      const sameTypeInWindow = ctx.alarms.filter(a => {
        if (a.aid === target.aid) {
          return false;
        }
        const ts = asUnixTs(a.ts);
        return a.type === target.type && ts >= tsLow && ts <= tsHigh;
      });

      const slim = (a: Alarm) => ({
        aid: a.aid,
        gid: a.gid,
        type: a.type,
        status: a.status,
        message: a.message,
        timestamp: unixToISOStringOrNow(a.ts),
        device: a.device,
        remote: a.remote,
      });

      const payload = {
        target: slim(target),
        window: {
          center: new Date(targetTs * 1000).toISOString(),
          window_seconds: windowSeconds,
          start: new Date(tsLow * 1000).toISOString(),
          end: new Date(tsHigh * 1000).toISOString(),
        },
        related: {
          same_device: sameDevice.slice(0, 25).map(slim),
          same_remote_ip: sameRemoteIp.slice(0, 25).map(slim),
          same_remote_domain: sameRemoteDomain.slice(0, 25).map(slim),
          same_type_in_window: sameTypeInWindow.slice(0, 50).map(slim),
        },
        counts: {
          same_device: sameDevice.length,
          same_remote_ip: sameRemoteIp.length,
          same_remote_domain: sameRemoteDomain.length,
          same_type_in_window: sameTypeInWindow.length,
        },
      };

      return this.createUnifiedResponse(payload);
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      return this.createErrorResponse(
        `Failed to get alarm context: ${msg}`,
        ErrorType.API_ERROR
      );
    }
  }
}

export class GetTargetTimelineHandler extends BaseToolHandler {
  name = 'get_target_timeline';
  description =
    'Build a chronological timeline of events for a target (IP, domain, or device id): alarms touching the target, blocked/allowed flows in the window, and any matching rule entries. Each entry has a `kind` discriminator (alarm | flow | rule). Use this for narrative reconstruction across signal types.';
  category = 'investigation' as const;

  constructor() {
    super({
      enableGeoEnrichment: true,
      enableFieldNormalization: true,
      additionalMeta: {
        data_source: 'investigation_timeline',
        entity_type: 'investigation_timeline',
      },
    });
  }

  async execute(
    args: ToolArgs,
    firewalla: FirewallaClient
  ): Promise<ToolResponse> {
    try {
      const targetValidation = ParameterValidator.validateRequiredString(
        args.target,
        'target'
      );
      if (!targetValidation.isValid) {
        return this.createErrorResponse(
          'Parameter validation failed',
          ErrorType.VALIDATION_ERROR,
          undefined,
          targetValidation.errors
        );
      }
      const target = (targetValidation.sanitizedValue as string).trim();
      const lookbackHours = clampLookbackHours(args.lookback_hours);
      const targetKind: 'ip' | 'domain' | 'device' = isIPv4(target)
        ? 'ip'
        : isMacFormatted(target) || target.startsWith('mac:')
          ? 'device'
          : 'domain';

      const ctx = await fetchInvestigationContext(firewalla, lookbackHours);

      const flowsForTarget = ctx.flows.filter(f => {
        if (targetKind === 'ip') {
          return flowMatchesIp(f, target);
        }
        if (targetKind === 'domain') {
          return (
            f.destination?.name === target ||
            (f.destination?.name && f.destination.name.endsWith(target))
          );
        }
        // device
        return f.device?.id === target;
      });
      const alarmsForTarget = ctx.alarms.filter(a => {
        if (targetKind === 'ip') {
          return alarmMatchesIp(a, target);
        }
        if (targetKind === 'domain') {
          // Alarms expose the remote hostname under `remote.name`; some API
          // responses may also include `remote.domain`. Match either.
          const aDomain =
            (a.remote as { domain?: string } | undefined)?.domain ||
            a.remote?.name;
          return aDomain === target;
        }
        return a.device?.id === target;
      });
      const rulesForTarget = ctx.rules.filter(r => {
        if (targetKind === 'ip') {
          return ruleTargetsIp(r, target);
        }
        if (targetKind === 'domain') {
          return r.target?.value === target;
        }
        return r.scope?.value === target;
      });

      type TimelineEntry =
        | { kind: 'alarm'; ts: number; ts_iso: string; alarm: unknown }
        | { kind: 'flow'; ts: number; ts_iso: string; flow: unknown }
        | { kind: 'rule'; ts: number; ts_iso: string; rule: unknown };

      const entries: TimelineEntry[] = [];

      for (const a of alarmsForTarget) {
        const ts = asUnixTs(a.ts);
        entries.push({
          kind: 'alarm',
          ts,
          ts_iso: unixToISOStringOrNow(a.ts),
          alarm: {
            aid: a.aid,
            type: a.type,
            status: a.status,
            message: a.message,
            device: a.device,
            remote: a.remote,
          },
        });
      }
      for (const f of flowsForTarget) {
        const ts = asUnixTs(f.ts);
        entries.push({
          kind: 'flow',
          ts,
          ts_iso: unixToISOStringOrNow(f.ts),
          flow: {
            protocol: f.protocol,
            direction: f.direction,
            blocked: f.block,
            download: f.download,
            upload: f.upload,
            source_ip: f.source?.ip,
            destination_ip: f.destination?.ip,
            destination_name: f.destination?.name,
            region: f.region,
            category: f.category,
            device_ip: f.device?.ip,
          },
        });
      }
      for (const r of rulesForTarget) {
        const ts = asUnixTs(r.updateTs || r.ts);
        entries.push({
          kind: 'rule',
          ts,
          ts_iso: unixToISOStringOrNow(r.updateTs || r.ts),
          rule: {
            id: r.id,
            action: r.action,
            status: r.status,
            direction: r.direction,
            target: r.target,
            scope: r.scope,
            notes: r.notes,
          },
        });
      }

      entries.sort((a, b) => a.ts - b.ts);

      const payload = {
        target: { value: target, kind: targetKind },
        window: {
          start: new Date(ctx.windowStart * 1000).toISOString(),
          end: new Date(ctx.windowEnd * 1000).toISOString(),
          lookback_hours: lookbackHours,
        },
        counts: {
          total_events: entries.length,
          alarm_events: alarmsForTarget.length,
          flow_events: flowsForTarget.length,
          rule_events: rulesForTarget.length,
        },
        timeline: entries.slice(0, 250),
      };

      return this.createUnifiedResponse(payload);
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Unknown error';
      return this.createErrorResponse(
        `Failed to build target timeline: ${msg}`,
        ErrorType.API_ERROR
      );
    }
  }
}
