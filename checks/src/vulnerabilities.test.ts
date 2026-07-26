import { describe, expect, it } from 'vitest';
import { checkVulnerabilities } from './checks/vulnerabilities.js';
import { jsonResponse, makeCtx, mockFetch, textResponse } from './test-helpers.js';

describe('checkVulnerabilities', () => {
  it('returns info when there is no published package', async () => {
    const ctx = makeCtx({ remoteUrl: 'https://example.com' }, async () => textResponse(500));
    const res = await checkVulnerabilities(ctx);
    expect(res.id).toBe('vulns.osv');
    expect(res.policyRef).toBe('§4.1');
    expect(res.status).toBe('info');
  });

  it('passes when OSV returns no advisories', async () => {
    const fetchImpl = mockFetch([{ match: 'api.osv.dev', response: jsonResponse(200, { vulns: [] }) }]);
    const ctx = makeCtx({ npmPackage: '@acme/clean' }, fetchImpl);
    const res = await checkVulnerabilities(ctx);
    expect(res.status).toBe('pass');
  });

  it('queries the PyPI ecosystem for PyPI packages', async () => {
    const fetchImpl = mockFetch([
      {
        match: 'pypi.org/pypi',
        response: jsonResponse(200, { info: { version: '1.2.3' } }),
      },
      { match: 'api.osv.dev', response: jsonResponse(200, { vulns: [] }) },
    ]);
    const ctx = makeCtx({ pypiPackage: 'acme-mcp' }, fetchImpl);
    const res = await checkVulnerabilities(ctx);
    expect(res.status).toBe('pass');
    expect(res.summary).toMatch(/PyPI/);
  });

  it('fails when OSV returns advisories', async () => {
    const fetchImpl = mockFetch([
      {
        match: 'api.osv.dev',
        response: jsonResponse(200, {
          vulns: [{ id: 'GHSA-xxxx', summary: 'Prototype pollution' }],
        }),
      },
    ]);
    const ctx = makeCtx({ npmPackage: '@acme/vuln' }, fetchImpl);
    const res = await checkVulnerabilities(ctx);
    expect(res.status).toBe('fail');
    expect(res.evidence.some((e) => e.label === 'GHSA-xxxx')).toBe(true);
  });

  it('is unverifiable on OSV HTTP errors', async () => {
    const fetchImpl = mockFetch([{ match: 'api.osv.dev', response: textResponse(500) }]);
    const ctx = makeCtx({ npmPackage: '@acme/x' }, fetchImpl);
    const res = await checkVulnerabilities(ctx);
    expect(res.status).toBe('unverifiable');
  });
});
