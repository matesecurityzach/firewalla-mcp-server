/**
 * Parity test: every tool registered in ToolRegistry must have a matching
 * input-schema entry in src/server.ts (and vice versa). Drift between these
 * two surfaces is the most common source of "Unknown tool" or
 * "missing schema" runtime errors.
 *
 * Implementation: we parse the source of server.ts and extract every
 * top-level `name: '...'` literal that appears under `inputSchema:`-bearing
 * objects (i.e. tool entries inside the ListTools handler). We then compare
 * that set against the registered tool names.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ToolRegistry } from '../../src/tools/registry';

function extractToolSchemaNames(): string[] {
  const path = resolve(__dirname, '..', '..', 'src', 'server.ts');
  const source = readFileSync(path, 'utf8');

  // Match name: 'xxx', then within the same object literal an inputSchema: field.
  // We accept multi-line matches; tools span ~10-30 lines each.
  const pattern = /name:\s*'([a-z_][a-z0-9_]*)'\s*,\s*description:[^]*?inputSchema:/g;
  const names = new Set<string>();
  for (const match of source.matchAll(pattern)) {
    names.add(match[1]);
  }
  return Array.from(names).sort();
}

describe('Registry <-> ListTools schema parity', () => {
  it('every registered tool has a matching schema entry in server.ts', () => {
    const registry = new ToolRegistry();
    const registered = registry.getToolNames().sort();
    const schemaNames = extractToolSchemaNames();

    const missingSchemas = registered.filter(n => !schemaNames.includes(n));
    expect(missingSchemas).toEqual([]);
  });

  it('every schema entry in server.ts has a matching registered tool', () => {
    const registry = new ToolRegistry();
    const registered = registry.getToolNames().sort();
    const schemaNames = extractToolSchemaNames();

    const missingRegistrations = schemaNames.filter(n => !registered.includes(n));
    expect(missingRegistrations).toEqual([]);
  });

  it('registers exactly 37 tools', () => {
    const registry = new ToolRegistry();
    expect(registry.getToolNames().length).toBe(37);
  });
});
