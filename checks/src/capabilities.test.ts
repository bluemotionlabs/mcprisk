import { describe, expect, it } from 'vitest';
import { checkCapabilities, computeToolSchemaHash } from './checks/capabilities.js';
import { computeCapabilityRisk } from './scoring.js';
import type { RiskHit, ToolSurface } from './types.js';

/** Capability risk for a surface, the way runChecks derives it. */
const riskOf = (surface: ToolSurface) => computeCapabilityRisk([checkCapabilities(surface)]);

function remote(tools: Array<{ name: string; description?: string }>): ToolSurface {
  return { source: 'remote-tools-list', tools, sourceRiskHits: [] };
}

function pkg(hits: RiskHit[]): ToolSurface {
  return { source: 'package-source', tools: [], sourceRiskHits: hits };
}

describe('checkCapabilities', () => {
  it('passes when no high-risk signals are present', () => {
    const res = checkCapabilities(remote([{ name: 'list_docs', description: 'Lists public documentation pages.' }]));
    expect(res.id).toBe('capabilities.tool-surface');
    expect(res.status).toBe('pass');
  });

  it('rates process-execution Critical without failing the check', () => {
    // §2.4: a shell server is supposed to run shells. That is capability risk to
    // disclose, not a defect to grade down.
    const surface = remote([{ name: 'run_shell', description: 'Execute a shell command on the host.' }]);
    expect(checkCapabilities(surface).status).toBe('pass');
    expect(riskOf(surface)).toBe('critical');
  });

  it('rates credential-access plus network-egress Critical (§2 combination rule)', () => {
    // Credential access is only claimed from package source, where `process.env.X_KEY`
    // is direct evidence. Tool prose cannot establish it; see the regression test below.
    const res = checkCapabilities(
      pkg([
        { category: 'credential-access', pattern: 'process.env.API_KEY', file: 'src/auth.js' },
        { category: 'network-egress', pattern: 'fetch(', file: 'src/client.js' },
      ]),
    );
    expect(res.status).toBe('pass');
    expect(computeCapabilityRisk([res])).toBe('critical');
  });

  it('does not infer credential-access from a tool describing its own auth requirement', () => {
    // Regression: these two descriptions are how every authenticated API tool
    // documents itself. Treating them as credential access made ordinary tools
    // (quote_lifetime_license, list_applications) trip the toxic-flow fail rule.
    const res = checkCapabilities(
      remote([
        { name: 'list_applications', description: 'Lists applications. Requires an API key.' },
        { name: 'quote_lifetime_license', description: 'Quotes a license. Pass your access token.' },
      ]),
    );
    expect(res.status).toBe('pass');
    expect(res.summary).not.toMatch(/credential/i);
  });

  it('rates a filesystem capability High', () => {
    const surface = remote([{ name: 'write_file', description: 'Write or overwrite a file on disk.' }]);
    expect(checkCapabilities(surface).status).toBe('pass');
    expect(riskOf(surface)).toBe('high');
  });

  it('rates a network-egress capability High', () => {
    const surface = remote([{ name: 'fetch_url', description: 'Fetch a URL via HTTP request.' }]);
    expect(riskOf(surface)).toBe('high');
  });

  it('rates credential access alone Medium', () => {
    expect(riskOf(pkg([{ category: 'credential-access', pattern: 'process.env.TOKEN', file: 'c.ts' }]))).toBe('medium');
  });

  it('rates a clean surface Low and an uninspectable one Unknown', () => {
    expect(riskOf(remote([{ name: 'list_docs', description: 'Lists public documentation.' }]))).toBe('low');
    expect(riskOf({ source: 'none', tools: [], sourceRiskHits: [] })).toBe('unknown');
  });

  it('records detected capabilities as evidence so risk survives persistence', () => {
    // computeCapabilityRisk reads this back from a stored scan, which is what
    // makes regrading possible without rescanning every server.
    const res = checkCapabilities(
      pkg([
        { category: 'filesystem', pattern: 'writeFileSync', file: 'a.ts' },
        { category: 'network-egress', pattern: 'fetch(', file: 'b.ts' },
      ]),
    );
    const recorded = res.evidence.find((e) => e.label === 'Detected capabilities');
    expect(recorded?.value).toContain('filesystem');
    expect(recorded?.value).toContain('network-egress');
    expect(computeCapabilityRisk([JSON.parse(JSON.stringify(res))])).toBe('high');
  });

  it('is unverifiable when the tool surface cannot be inspected', () => {
    const res = checkCapabilities({ source: 'none', tools: [], sourceRiskHits: [] });
    expect(res.status).toBe('unverifiable');
  });

  it('uses sourceRiskHits for package-source surfaces', () => {
    const res = checkCapabilities(
      pkg([{ category: 'process-execution', pattern: 'child_process', label: 'child process execution', file: 'index.js' }]),
    );
    expect(res.status).toBe('pass');
    expect(computeCapabilityRisk([res])).toBe('critical');
    expect(res.evidence.some((e) => e.label.includes('process-execution'))).toBe(true);
  });
});

describe('computeToolSchemaHash', () => {
  it('is stable for identical tool lists', async () => {
    const tools = [{ name: 'a', description: 'A', inputSchema: { type: 'object' } }];
    const h1 = await computeToolSchemaHash(tools);
    const h2 = await computeToolSchemaHash(tools);
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
  });

  it('changes when description or schema changes', async () => {
    const base = [{ name: 'a', description: 'A', inputSchema: { type: 'object' } }];
    const changedDesc = [{ name: 'a', description: 'B', inputSchema: { type: 'object' } }];
    const changedSchema = [{ name: 'a', description: 'A', inputSchema: { type: 'string' } }];
    const h0 = await computeToolSchemaHash(base);
    expect(await computeToolSchemaHash(changedDesc)).not.toBe(h0);
    expect(await computeToolSchemaHash(changedSchema)).not.toBe(h0);
  });

  it('is order-independent (tools are sorted by name)', async () => {
    const a = [
      { name: 'zeta', description: 'z' },
      { name: 'alpha', description: 'a' },
    ];
    const b = [
      { name: 'alpha', description: 'a' },
      { name: 'zeta', description: 'z' },
    ];
    expect(await computeToolSchemaHash(a)).toBe(await computeToolSchemaHash(b));
  });
});
