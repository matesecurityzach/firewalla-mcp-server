import {
  GenerateSecurityReportHandler,
  GenerateThreatAnalysisHandler,
  GenerateBandwidthAnalysisHandler,
  GenerateDeviceInvestigationReportHandler,
  GenerateNetworkHealthReportHandler,
} from '../../../src/tools/handlers/reports';
import type { FirewallaClient } from '../../../src/firewalla/client';

function parsePayload(resp: { content: Array<{ text: string }>; isError?: boolean }): any {
  return JSON.parse(resp.content[0].text);
}

function makeClient(): jest.Mocked<FirewallaClient> {
  return {
    getActiveAlarms: jest.fn().mockResolvedValue({
      count: 1,
      results: [
        {
          aid: 1,
          gid: 'box-1',
          ts: 1700000000,
          type: 1,
          status: 1,
          message: 'Security activity',
          device: { id: 'mac:AA', name: 'Device-A', ip: '192.168.1.10' },
          remote: { id: 'r', name: 'evil', ip: '1.2.3.4' },
        },
      ],
    }),
    getFirewallSummary: jest.fn().mockResolvedValue({
      status: 'online',
      uptime: 1000000,
      cpu_usage: 25,
      memory_usage: 40,
      active_connections: 200,
      blocked_attempts: 5,
      last_updated: new Date().toISOString(),
    }),
    getSecurityMetrics: jest.fn().mockResolvedValue({
      total_alarms: 12,
      active_alarms: 4,
      blocked_connections: 100,
      suspicious_activities: 3,
      threat_level: 'medium',
      last_threat_detected: new Date().toISOString(),
    }),
    getRecentThreats: jest.fn().mockResolvedValue([
      {
        timestamp: new Date().toISOString(),
        type: 'Blocked Connection',
        source_ip: '192.168.1.10',
        destination_ip: '1.2.3.4',
        action_taken: 'blocked',
        severity: 'medium',
      },
    ]),
    getNetworkRules: jest.fn().mockResolvedValue({
      count: 2,
      results: [
        { id: 'r1', status: 'active', action: 'block', direction: 'bidirection', target: { type: 'ip', value: '1.2.3.4' }, ts: 1, updateTs: 1 },
        { id: 'r2', status: 'paused', action: 'block', direction: 'bidirection', target: { type: 'ip', value: '5.6.7.8' }, ts: 1, updateTs: 1 },
      ],
    }),
    getBandwidthUsage: jest.fn().mockResolvedValue({
      count: 1,
      results: [
        {
          device_id: 'mac:AA',
          device_name: 'Device-A',
          ip: '192.168.1.10',
          bytes_uploaded: 200 * 1024 * 1024,
          bytes_downloaded: 800 * 1024 * 1024,
          total_bytes: 1000 * 1024 * 1024,
          period: '24h',
        },
      ],
    }),
    getDeviceStatus: jest.fn().mockResolvedValue({
      count: 1,
      results: [
        {
          id: 'mac:AA',
          gid: 'box-1',
          name: 'Device-A',
          ip: '192.168.1.10',
          online: true,
          ipReserved: false,
          network: { id: 'n', name: 'Home' },
          totalDownload: 0,
          totalUpload: 0,
          macVendor: 'Acme',
          lastSeen: 1700000000,
        },
      ],
      next_cursor: undefined,
      total_count: 1,
      has_more: false,
    }),
    getFlowData: jest.fn().mockResolvedValue({
      count: 1,
      results: [
        {
          ts: 1700000000,
          gid: 'box-1',
          protocol: 'tcp',
          direction: 'outbound',
          block: false,
          download: 1024,
          upload: 256,
          count: 1,
          duration: 5,
          device: { id: 'mac:AA', name: 'Device-A', ip: '192.168.1.10' },
          source: { id: 's', name: 's', ip: '192.168.1.10' },
          destination: { id: 'd', name: 'evil', ip: '1.2.3.4' },
        },
      ],
    }),
    getNetworkTopology: jest.fn().mockResolvedValue({
      subnets: [{ id: 'n', name: 'Home', cidr: '192.168.1.0/24', device_count: 1 }],
      connections: [],
    }),
  } as unknown as jest.Mocked<FirewallaClient>;
}

describe('report tool handlers', () => {
  it('generate_security_report returns data + narrative', async () => {
    const handler = new GenerateSecurityReportHandler();
    const resp = await handler.execute({} as any, makeClient());
    const payload = parsePayload(resp).data;
    expect(payload.data.period).toBe('24h');
    expect(typeof payload.narrative).toBe('string');
    expect(payload.narrative).toContain('Firewalla Security Report');
  });

  it('generate_threat_analysis returns data + narrative', async () => {
    const handler = new GenerateThreatAnalysisHandler();
    const resp = await handler.execute(
      { severity_threshold: 'high' } as any,
      makeClient()
    );
    const payload = parsePayload(resp).data;
    expect(payload.data.severity_threshold).toBe('high');
    expect(payload.data.threat_patterns).toBeDefined();
    expect(payload.narrative).toContain('Threat Analysis');
  });

  it('generate_bandwidth_analysis_report rejects missing period', async () => {
    const handler = new GenerateBandwidthAnalysisHandler();
    const resp = await handler.execute({} as any, makeClient());
    expect(resp.isError).toBe(true);
  });

  it('generate_bandwidth_analysis_report returns data + narrative when period given', async () => {
    const handler = new GenerateBandwidthAnalysisHandler();
    const resp = await handler.execute(
      { period: '24h', threshold_mb: 500 } as any,
      makeClient()
    );
    const payload = parsePayload(resp).data;
    expect(payload.data.period).toBe('24h');
    expect(payload.data.threshold_mb).toBe(500);
    expect(payload.narrative).toContain('Bandwidth Usage Analysis');
  });

  it('generate_device_investigation_report rejects missing device_id', async () => {
    const handler = new GenerateDeviceInvestigationReportHandler();
    const resp = await handler.execute({} as any, makeClient());
    expect(resp.isError).toBe(true);
  });

  it('generate_device_investigation_report errors on unknown device', async () => {
    const handler = new GenerateDeviceInvestigationReportHandler();
    const resp = await handler.execute(
      { device_id: 'mac:NOTREAL' } as any,
      makeClient()
    );
    expect(resp.isError).toBe(true);
  });

  it('generate_device_investigation_report returns data + narrative for known device', async () => {
    const handler = new GenerateDeviceInvestigationReportHandler();
    const resp = await handler.execute(
      { device_id: 'mac:AA' } as any,
      makeClient()
    );
    const payload = parsePayload(resp).data;
    expect(payload.data.device.id).toBe('mac:AA');
    expect(payload.narrative).toContain('Device Investigation Report');
  });

  it('generate_network_health_report returns scores + narrative', async () => {
    const handler = new GenerateNetworkHealthReportHandler();
    const resp = await handler.execute({} as any, makeClient());
    const payload = parsePayload(resp).data;
    expect(typeof payload.data.health_score).toBe('number');
    expect(typeof payload.data.performance_score).toBe('number');
    expect(typeof payload.data.security_score).toBe('number');
    expect(payload.narrative).toContain('Network Health Assessment');
  });
});
