import {
  InvestigateIpHandler,
  InvestigateDeviceHandler,
  GetAlarmContextHandler,
  GetTargetTimelineHandler,
} from '../../../src/tools/handlers/investigation';
import type { FirewallaClient } from '../../../src/firewalla/client';

function makeFlow(overrides: Record<string, unknown> = {}): any {
  return {
    ts: Math.floor(Date.now() / 1000),
    protocol: 'tcp',
    direction: 'outbound',
    block: false,
    download: 0,
    upload: 0,
    count: 1,
    device: { id: 'mac:AA:BB:CC:DD:EE:01', name: 'Device-A', ip: '192.168.1.10' },
    ...overrides,
  };
}

function makeAlarm(overrides: Record<string, unknown> = {}): any {
  return {
    aid: 1001,
    gid: 'box-1',
    ts: Math.floor(Date.now() / 1000),
    type: 1,
    status: 1,
    message: 'Security activity',
    device: { id: 'mac:AA:BB:CC:DD:EE:01', name: 'Device-A', ip: '192.168.1.10' },
    remote: { id: 'rem', name: 'evil.example', ip: '203.0.113.5' },
    ...overrides,
  };
}

function makeRule(overrides: Record<string, unknown> = {}): any {
  return {
    id: 'rule-1',
    action: 'block',
    target: { type: 'ip', value: '203.0.113.5' },
    direction: 'bidirection',
    status: 'active',
    ts: Math.floor(Date.now() / 1000),
    updateTs: Math.floor(Date.now() / 1000),
    ...overrides,
  };
}

function makeDevice(overrides: Record<string, unknown> = {}): any {
  return {
    id: 'mac:AA:BB:CC:DD:EE:01',
    gid: 'box-1',
    name: 'Device-A',
    ip: '192.168.1.10',
    online: true,
    ipReserved: false,
    network: { id: 'net-1', name: 'Home' },
    totalDownload: 0,
    totalUpload: 0,
    macVendor: 'Acme',
    mac: 'AA:BB:CC:DD:EE:01',
    ...overrides,
  };
}

function makeClient(opts: {
  flows?: any[];
  alarms?: any[];
  rules?: any[];
  devices?: any[];
  specificAlarm?: any;
}): jest.Mocked<FirewallaClient> {
  const client = {
    getFlowData: jest
      .fn()
      .mockResolvedValue({ count: opts.flows?.length || 0, results: opts.flows || [] }),
    getActiveAlarms: jest
      .fn()
      .mockResolvedValue({ count: opts.alarms?.length || 0, results: opts.alarms || [] }),
    getNetworkRules: jest
      .fn()
      .mockResolvedValue({ count: opts.rules?.length || 0, results: opts.rules || [] }),
    getDeviceStatus: jest.fn().mockResolvedValue({
      count: opts.devices?.length || 0,
      results: opts.devices || [],
      next_cursor: undefined,
      total_count: opts.devices?.length || 0,
      has_more: false,
    }),
    getSpecificAlarm: jest.fn().mockResolvedValue(
      opts.specificAlarm
        ? { count: 1, results: [opts.specificAlarm] }
        : { count: 0, results: [] }
    ),
  } as unknown as jest.Mocked<FirewallaClient>;
  return client;
}

function parsePayload(resp: { content: Array<{ text: string }> }): any {
  return JSON.parse(resp.content[0].text);
}

describe('investigation handlers', () => {
  describe('InvestigateIpHandler', () => {
    it('rejects missing ip', async () => {
      const handler = new InvestigateIpHandler();
      const resp = await handler.execute({} as any, makeClient({}));
      expect(resp.isError).toBe(true);
    });

    it('correlates flows, alarms, rules, and device for a target IP', async () => {
      const ip = '192.168.1.10';
      const handler = new InvestigateIpHandler();
      const client = makeClient({
        flows: [
          makeFlow({
            source: { id: 's', name: 's', ip },
            destination: { id: 'd', name: 'd', ip: '203.0.113.5' },
            region: 'US',
          }),
          makeFlow({
            source: { id: 's', name: 's', ip: '203.0.113.5' },
            destination: { id: 'd', name: 'd', ip },
            direction: 'inbound',
          }),
          makeFlow({ block: true, source: { id: 's', name: 's', ip } }),
        ],
        alarms: [makeAlarm()],
        rules: [makeRule({ target: { type: 'ip', value: ip } })],
        devices: [makeDevice({ ip })],
      });

      const resp = await handler.execute({ ip, lookback_hours: 12 } as any, client);
      const payload = parsePayload(resp).data;
      expect(payload.target.ip).toBe(ip);
      expect(payload.summary.flow_count).toBe(3);
      expect(payload.summary.matching_rule_count).toBe(1);
      expect(payload.summary.alarm_count).toBe(1);
      expect(payload.device).toBeTruthy();
      expect(payload.device.ip).toBe(ip);
    });
  });

  describe('InvestigateDeviceHandler', () => {
    it('errors with a hint when the device is unknown', async () => {
      const handler = new InvestigateDeviceHandler();
      const client = makeClient({ devices: [] });
      const resp = await handler.execute(
        { device: 'mac:00:00:00:00:00:00' } as any,
        client
      );
      expect(resp.isError).toBe(true);
    });

    it('resolves by IP and aggregates flows + alarms', async () => {
      const handler = new InvestigateDeviceHandler();
      const ip = '192.168.1.10';
      const client = makeClient({
        devices: [makeDevice({ ip })],
        flows: [makeFlow({ source: { id: 's', name: 's', ip } })],
        alarms: [makeAlarm()],
        rules: [makeRule({ scope: { type: 'device', value: 'mac:AA:BB:CC:DD:EE:01' } })],
      });
      const resp = await handler.execute(
        { device: ip, lookback_hours: 6 } as any,
        client
      );
      const payload = parsePayload(resp).data;
      expect(payload.device.id).toBe('mac:AA:BB:CC:DD:EE:01');
      expect(payload.summary.flow_count).toBe(1);
      expect(payload.summary.alarm_count).toBe(1);
      expect(payload.summary.matching_rule_count).toBe(1);
    });
  });

  describe('GetAlarmContextHandler', () => {
    it('returns target + related groupings', async () => {
      const target = makeAlarm({ aid: 9001 });
      const sameDevice = makeAlarm({ aid: 9002 });
      const sameRemote = makeAlarm({
        aid: 9003,
        device: { id: 'mac:OTHER', name: 'Other', ip: '10.0.0.1' },
      });
      const handler = new GetAlarmContextHandler();
      const client = makeClient({
        specificAlarm: target,
        alarms: [target, sameDevice, sameRemote],
      });
      const resp = await handler.execute(
        { alarm_id: '9001', box: 'box-1' } as any,
        client
      );
      const payload = parsePayload(resp).data;
      expect(payload.target.aid).toBe(9001);
      expect(payload.counts.same_device).toBeGreaterThanOrEqual(1);
      expect(payload.counts.same_remote_ip).toBeGreaterThanOrEqual(1);
    });

    it('errors when target alarm is not found', async () => {
      const handler = new GetAlarmContextHandler();
      const client = makeClient({});
      const resp = await handler.execute({ alarm_id: '404' } as any, client);
      expect(resp.isError).toBe(true);
    });
  });

  describe('GetTargetTimelineHandler', () => {
    it('builds an ordered timeline with kind discriminators', async () => {
      const ip = '203.0.113.5';
      const oldFlow = makeFlow({
        ts: Math.floor(Date.now() / 1000) - 600,
        destination: { id: 'd', name: 'evil.example', ip },
      });
      const newAlarm = makeAlarm({
        ts: Math.floor(Date.now() / 1000) - 60,
        remote: { id: 'rem', name: 'evil.example', ip },
      });
      const handler = new GetTargetTimelineHandler();
      const client = makeClient({
        flows: [oldFlow],
        alarms: [newAlarm],
        rules: [makeRule({ target: { type: 'ip', value: ip } })],
      });
      const resp = await handler.execute(
        { target: ip, lookback_hours: 1 } as any,
        client
      );
      const payload = parsePayload(resp).data;
      expect(payload.target.kind).toBe('ip');
      expect(payload.counts.total_events).toBeGreaterThanOrEqual(3);
      const kinds = (payload.timeline as Array<{ kind: string }>).map(e => e.kind);
      expect(kinds).toEqual(expect.arrayContaining(['alarm', 'flow', 'rule']));
      // Sorted ascending by ts: old flow should come before the recent alarm.
      const flowIndex = kinds.indexOf('flow');
      const alarmIndex = kinds.indexOf('alarm');
      expect(flowIndex).toBeLessThan(alarmIndex);
    });

    it('detects domain targets', async () => {
      const handler = new GetTargetTimelineHandler();
      const client = makeClient({
        flows: [
          makeFlow({
            destination: { id: 'd', name: 'evil.example', ip: '203.0.113.5' },
          }),
        ],
        alarms: [
          makeAlarm({
            remote: {
              id: 'rem',
              name: 'evil.example',
              ip: '203.0.113.5',
              domain: 'evil.example',
            },
          }),
        ],
      });
      const resp = await handler.execute(
        { target: 'evil.example', lookback_hours: 1 } as any,
        client
      );
      const payload = parsePayload(resp).data;
      expect(payload.target.kind).toBe('domain');
    });
  });
});
