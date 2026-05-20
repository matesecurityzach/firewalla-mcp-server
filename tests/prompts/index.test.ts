import { setupPrompts, PROMPT_CATALOG } from '../../src/prompts/index';
import { FirewallaClient } from '../../src/firewalla/client';
import {
  GetPromptRequestSchema,
  ListPromptsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

// Mock the FirewallaClient
jest.mock('../../src/firewalla/client');
const MockedFirewallaClient = FirewallaClient as jest.MockedClass<typeof FirewallaClient>;

type Handler = (request: any) => Promise<any>;

function buildMockServer(): { server: any; handlers: Map<unknown, Handler> } {
  const handlers = new Map<unknown, Handler>();
  const server = {
    setRequestHandler: jest.fn((schema: unknown, handler: Handler) => {
      handlers.set(schema, handler);
    }),
  };
  return { server, handlers };
}

describe('MCP Prompts Setup', () => {
  let mockFirewalla: jest.Mocked<FirewallaClient>;

  beforeEach(() => {
    jest.clearAllMocks();
    mockFirewalla = new MockedFirewallaClient({} as any) as jest.Mocked<FirewallaClient>;
  });

  it('registers both ListPrompts and GetPrompt handlers', () => {
    const { server, handlers } = buildMockServer();
    setupPrompts(server, mockFirewalla);
    expect(server.setRequestHandler).toHaveBeenCalledTimes(2);
    expect(handlers.has(ListPromptsRequestSchema)).toBe(true);
    expect(handlers.has(GetPromptRequestSchema)).toBe(true);
  });

  it('ListPrompts mirrors PROMPT_CATALOG', async () => {
    const { server, handlers } = buildMockServer();
    setupPrompts(server, mockFirewalla);
    const list = handlers.get(ListPromptsRequestSchema)!;
    const result = await list({} as any);
    expect(result.prompts).toHaveLength(PROMPT_CATALOG.length);
    const names = (result.prompts as Array<{ name: string }>).map(p => p.name);
    expect(names).toEqual(PROMPT_CATALOG.map(p => p.name));
  });

  it('should be defined and exportable', () => {
    expect(setupPrompts).toBeDefined();
    expect(typeof setupPrompts).toBe('function');
  });
});
