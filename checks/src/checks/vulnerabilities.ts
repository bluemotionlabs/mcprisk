/**
 * §4.1 Known vulnerabilities - OSV.dev lookup for the published package.
 * Direct dependencies are deferred to a later version; the package itself
 * is the highest-signal, lowest-noise query.
 */

import type { CheckContext, CheckResult, Evidence } from '../types.js';
import { errMsg, fetchWithTimeout } from '../utils.js';

export async function checkVulnerabilities(ctx: CheckContext): Promise<CheckResult> {
  const base = {
    id: 'vulns.osv',
    policyRef: '§4.1',
    title: 'No known vulnerabilities (OSV.dev)',
  };

  const npm = ctx.target.npmPackage;
  const pypi = ctx.target.pypiPackage;
  if (!npm && !pypi) {
    return { ...base, status: 'info', summary: 'No package to query (remote-only server).', evidence: [] };
  }

  // Prefer npm when both are present (same preference as canonical identity).
  const ecosystem = npm ? 'npm' : 'PyPI';
  const pkg = (npm ?? pypi)!;

  let latestVersion: string | undefined;
  try {
    if (ecosystem === 'npm') {
      const metaRes = await fetchWithTimeout(ctx, `https://registry.npmjs.org/${encodeURIComponent(pkg)}`);
      if (metaRes.ok) {
        const meta = (await metaRes.json()) as { 'dist-tags'?: Record<string, string> };
        latestVersion = meta['dist-tags']?.latest;
      }
    } else {
      const metaRes = await fetchWithTimeout(ctx, `https://pypi.org/pypi/${encodeURIComponent(pkg)}/json`);
      if (metaRes.ok) {
        const meta = (await metaRes.json()) as { info?: { version?: string } };
        latestVersion = meta.info?.version;
      }
    }
  } catch {
    // version lookup is best-effort; fall back to package-name-only OSV query
  }

  const queryBody: { package: { name: string; ecosystem: string; version?: string } } = {
    package: { name: pkg, ecosystem },
  };
  if (latestVersion) {
    queryBody.package.version = latestVersion;
  }

  try {
    const res = await fetchWithTimeout(ctx, 'https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(queryBody),
    });
    if (!res.ok) {
      return { ...base, status: 'unverifiable', summary: `OSV.dev error (HTTP ${res.status}).`, evidence: [], degraded: true };
    }
    const body = (await res.json()) as { vulns?: Array<{ id: string; summary?: string }> };
    const vulns = body.vulns ?? [];

    const summaryVersion = latestVersion ? ` @${latestVersion}` : '';
    if (vulns.length === 0) {
      return {
        ...base,
        status: 'pass',
        summary: `No advisories on record for ${pkg}${summaryVersion} (${ecosystem}).`,
        evidence: [],
      };
    }
    const evidence: Evidence[] = vulns.slice(0, 10).map((v) => ({
      label: v.id,
      value: v.summary,
      url: `https://osv.dev/vulnerability/${v.id}`,
    }));
    return {
      ...base,
      status: 'fail',
      summary: `${vulns.length} advisory(ies) on record for ${pkg}${summaryVersion} (${ecosystem}) - review whether the evaluated version is affected.`,
      evidence,
    };
  } catch (err) {
    return { ...base, status: 'unverifiable', summary: `OSV.dev unreachable: ${errMsg(err)}`, evidence: [], degraded: true };
  }
}
