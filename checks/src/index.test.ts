import { describe, expect, it } from 'vitest';
import { runChecks } from './index.js';
import { jsonResponse, makeCtx, mockFetch, textResponse } from './test-helpers.js';

describe('runChecks', () => {
  it('produces a full ScanReport for a remote server with clean tools', async () => {
    let callCount = 0;
    const fetchImpl = mockFetch([
      {
        match: 'example.com',
        response: (url: string) => {
          if (url.includes('oauth-protected-resource')) {
            return textResponse(404);
          }
          callCount++;
          if (callCount <= 2) {
            return jsonResponse(200, {
              result: {
                capabilities: {},
                instructions: 'Use these tools carefully.',
                serverInfo: { name: 'test-server', version: '1.0.0' },
              },
            });
          }
          return jsonResponse(200, {
            result: {
              tools: [{ name: 'clean_tool', description: 'A safe tool for reading docs.' }],
            },
          });
        },
      },
      {
        match: 'registry.modelcontextprotocol.io',
        response: () => jsonResponse(200, { servers: [] }),
      },
    ]);

    const ctx = makeCtx({ remoteUrl: 'https://example.com/mcp' }, fetchImpl);
    const report = await runChecks(ctx);

    expect(report.score).toBeDefined();
    expect(report.grade).toBeDefined();
    expect(report.toolSource).toBe('remote-tools-list');
    expect(report.checks.length).toBeGreaterThanOrEqual(8);
    expect(report.checks.some((c) => c.id === 'capabilities.tool-surface')).toBe(true);
    expect(report.checks.some((c) => c.id === 'poisoning.patterns')).toBe(true);
    expect(report.checks.some((c) => c.id === 'transport.https')).toBe(true);
    expect(report.checks.some((c) => c.id === 'transport.auth-required')).toBe(true);
    expect(report.checks.some((c) => c.id === 'transport.oauth-metadata')).toBe(true);
    expect(report.checks.some((c) => c.id === 'vulns.osv')).toBe(true);
    expect(report.checks.some((c) => c.id === 'provenance.registry-listed')).toBe(true);
    expect(report.checks.some((c) => c.id === 'provenance.repo-health')).toBe(true);
    expect(report.checks.some((c) => c.id === 'provenance.package-hygiene')).toBe(true);
  });

  it('rates dangerous capabilities as risk and propagates that to auth gating', async () => {
    let callCount = 0;
    const fetchImpl = mockFetch([
      {
        match: 'example.com',
        response: (url: string) => {
          if (url.includes('oauth-protected-resource')) {
            return textResponse(404);
          }
          callCount++;
          if (callCount <= 2) {
            return jsonResponse(200, {
              result: {
                capabilities: { tools: {} },
                serverInfo: { name: 'danger', version: '1.0.0' },
              },
            });
          }
          return jsonResponse(200, {
            result: {
              tools: [{ name: 'run_shell', description: 'Execute shell commands.' }],
            },
          });
        },
      },
      {
        match: 'registry.modelcontextprotocol.io',
        response: () => jsonResponse(200, { servers: [] }),
      },
    ]);

    const ctx = makeCtx({ remoteUrl: 'https://example.com/mcp' }, fetchImpl);
    const report = await runChecks(ctx);

    // The shell tool no longer fails §2; it sets the capability axis to Critical,
    // and §3.2 still fails because an anonymous server at Medium+ risk is a fail.
    const capability = report.checks.find((c) => c.id === 'capabilities.tool-surface');
    expect(capability?.status).toBe('pass');
    expect(report.capabilityRisk).toBe('critical');

    const authRequired = report.checks.find((c) => c.id === 'transport.auth-required');
    expect(authRequired?.status).toBe('fail');
  });

  it('computes tool schema hash when real tools are retrieved', async () => {
    let callCount = 0;
    const fetchImpl = mockFetch([
      {
        match: 'example.com',
        response: (url: string) => {
          if (url.includes('oauth-protected-resource')) {
            return textResponse(404);
          }
          callCount++;
          if (callCount <= 2) {
            return jsonResponse(200, {
              result: { capabilities: { tools: {} }, serverInfo: { name: 's', version: '1.0.0' } },
            });
          }
          return jsonResponse(200, {
            result: {
              tools: [{ name: 'tool_a', description: 'Does A.' }],
            },
          });
        },
      },
      {
        match: 'registry.modelcontextprotocol.io',
        response: () => jsonResponse(200, { servers: [] }),
      },
    ]);

    const ctx = makeCtx({ remoteUrl: 'https://example.com/mcp' }, fetchImpl);
    const report = await runChecks(ctx);

    expect(report.toolSchemaHash).toMatch(/^[0-9a-f]{64}$/);
    expect(report.tools).toHaveLength(1);
  });
});
