import { setupResources, RESOURCE_CATALOG } from '../../src/resources/index';
import {
  ALARM_TYPES,
  CONTENT_CATEGORIES,
  QUERY_SYNTAX,
} from '../../src/resources/reference';
import { FirewallaClient } from '../../src/firewalla/client';
import {
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

// Mock the FirewallaClient
jest.mock('../../src/firewalla/client');
const MockedFirewallaClient = FirewallaClient as jest.MockedClass<typeof FirewallaClient>;

type Handler = (request: any) => Promise<any>;

function buildMockServer(): {
  server: any;
  handlers: Map<unknown, Handler>;
} {
  const handlers = new Map<unknown, Handler>();
  const server = {
    setRequestHandler: jest.fn((schema: unknown, handler: Handler) => {
      handlers.set(schema, handler);
    }),
  };
  return { server, handlers };
}

describe('MCP Resources Setup', () => {
  let mockFirewalla: jest.Mocked<FirewallaClient>;

  beforeEach(() => {
    jest.clearAllMocks();
    mockFirewalla = new MockedFirewallaClient({} as any) as jest.Mocked<FirewallaClient>;
  });

  it('should register ListResourcesRequestSchema and ReadResourceRequestSchema handlers', () => {
    const { server, handlers } = buildMockServer();
    setupResources(server, mockFirewalla);
    expect(server.setRequestHandler).toHaveBeenCalledTimes(2);
    expect(handlers.has(ListResourcesRequestSchema)).toBe(true);
    expect(handlers.has(ReadResourceRequestSchema)).toBe(true);
  });

  it('ListResources returns the catalog including the new reference URIs', async () => {
    const { server, handlers } = buildMockServer();
    setupResources(server, mockFirewalla);
    const listHandler = handlers.get(ListResourcesRequestSchema)!;
    const result = await listHandler({} as any);
    const uris = (result.resources as Array<{ uri: string }>).map(r => r.uri);
    expect(uris).toEqual(expect.arrayContaining([
      'firewalla://summary',
      'firewalla://devices',
      'firewalla://metrics/security',
      'firewalla://topology',
      'firewalla://threats/recent',
      'firewalla://boxes',
      'firewalla://reference/alarm-types',
      'firewalla://reference/categories',
      'firewalla://reference/query-syntax',
    ]));
    expect(uris.length).toBe(RESOURCE_CATALOG.length);
  });

  it('firewalla://reference/alarm-types returns the full alarm-type table', async () => {
    const { server, handlers } = buildMockServer();
    setupResources(server, mockFirewalla);
    const readHandler = handlers.get(ReadResourceRequestSchema)!;
    const result = await readHandler({
      params: { uri: 'firewalla://reference/alarm-types' },
    });
    const payload = JSON.parse(result.contents[0].text);
    expect(payload.alarm_types).toHaveLength(ALARM_TYPES.length);
    expect(payload.alarm_types[0]).toMatchObject({ id: 1, name: 'Security Activity' });
  });

  it('firewalla://reference/categories returns the verified category list', async () => {
    const { server, handlers } = buildMockServer();
    setupResources(server, mockFirewalla);
    const readHandler = handlers.get(ReadResourceRequestSchema)!;
    const result = await readHandler({
      params: { uri: 'firewalla://reference/categories' },
    });
    const payload = JSON.parse(result.contents[0].text);
    expect(payload.categories).toHaveLength(CONTENT_CATEGORIES.length);
    const names = (payload.categories as Array<{ name: string }>).map(c => c.name);
    expect(names).toEqual(expect.arrayContaining(['intel', 'porn', 'social']));
  });

  it('firewalla://reference/query-syntax returns grammar + qualifier tables', async () => {
    const { server, handlers } = buildMockServer();
    setupResources(server, mockFirewalla);
    const readHandler = handlers.get(ReadResourceRequestSchema)!;
    const result = await readHandler({
      params: { uri: 'firewalla://reference/query-syntax' },
    });
    const payload = JSON.parse(result.contents[0].text);
    expect(payload.forms).toEqual(QUERY_SYNTAX.forms);
    expect(payload.qualifiers.flows).toBeDefined();
    expect(payload.qualifiers.alarms).toBeDefined();
    expect(payload.qualifiers.rules).toBeDefined();
  });

  it('firewalla://boxes calls getBoxes and reshapes the response', async () => {
    const { server, handlers } = buildMockServer();
    (mockFirewalla as any).getBoxes = jest.fn().mockResolvedValue({
      count: 1,
      results: [
        {
          gid: 'box-gid-1',
          name: 'Test Box',
          model: 'gold',
          mode: 'router',
          version: '1.975',
          online: true,
          lastSeen: 1700000000,
          license: 'lic',
          publicIP: '1.2.3.4',
          group: undefined,
          location: 'US',
          deviceCount: 12,
          ruleCount: 3,
          alarmCount: 1,
        },
      ],
    });
    setupResources(server, mockFirewalla);
    const readHandler = handlers.get(ReadResourceRequestSchema)!;
    const result = await readHandler({
      params: { uri: 'firewalla://boxes' },
    });
    const payload = JSON.parse(result.contents[0].text);
    expect(payload.total).toBe(1);
    expect(payload.boxes[0]).toMatchObject({
      gid: 'box-gid-1',
      device_count: 12,
      rule_count: 3,
      alarm_count: 1,
    });
  });

  it('should be defined and exportable', () => {
    expect(setupResources).toBeDefined();
    expect(typeof setupResources).toBe('function');
  });
});