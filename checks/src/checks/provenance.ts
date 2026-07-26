/**
 * §1.1 Registry presence + §1.2 Source repository health.
 *
 * Provenance is the cheapest attack vector to close: an MCP server is a
 * supply-chain dependency with agent-level privileges, so "where does this
 * come from and is anyone maintaining it" is checked before anything else.
 * Same signal family as OpenSSF Scorecard, scoped to what matters pre-adoption.
 */

import type { CheckContext, CheckResult, Evidence } from '../types.js';
import { errMsg, fetchWithTimeout } from '../utils.js';

const REGISTRY_BASE = 'https://registry.modelcontextprotocol.io';
/** Commits older than this are a warn; repos are often "done" but agents-facing code rots fast. */
const STALE_PUSH_DAYS = 365;

export async function checkRegistryListed(ctx: CheckContext): Promise<CheckResult> {
  const base = {
    id: 'provenance.registry-listed',
    policyRef: '§1.1',
    title: 'Listed on the official MCP registry',
  };

  const query = ctx.target.registryName ?? ctx.target.npmPackage ?? ctx.target.github?.repo;
  if (!query) {
    return { ...base, status: 'unverifiable', summary: 'No identifier available to search the registry.', evidence: [] };
  }

  // Registry names (io.github.owner/thing) rarely equal npm names (@scope/server-thing),
  // so fall back to the bare name: "@modelcontextprotocol/server-filesystem" → "filesystem".
  const bareName = query.split('/').pop()?.replace(/^(mcp-|server-)+/, '').replace(/(-mcp|-server)+$/, '');
  const queries = bareName && bareName !== query ? [query, bareName] : [query];

  try {
    let match: Record<string, unknown> | undefined;
    for (const q of queries) {
      const res = await fetchWithTimeout(ctx, `${REGISTRY_BASE}/v0/servers?search=${encodeURIComponent(q)}&limit=50`);
      if (!res.ok) {
        return {
          ...base,
          status: 'unverifiable',
          summary: `Registry query failed (HTTP ${res.status}).`,
          evidence: [],
          degraded: true,
        };
      }
      const body = (await res.json()) as { servers?: Array<{ server?: Record<string, unknown> }> };
      // Entries are wrapped: {server: {...}, _meta: {...}}, one entry per published version.
      match = (body.servers ?? [])
        .map((s) => s.server)
        .filter((s): s is Record<string, unknown> => Boolean(s))
        .find((s) => matchesTarget(s, ctx));
      if (match) break;
    }

    if (match) {
      const name = String(match['name'] ?? query);
      return {
        ...base,
        status: 'pass',
        summary: `Listed on registry.modelcontextprotocol.io as ${name}.`,
        evidence: [{ label: 'Registry entry', value: name, url: `${REGISTRY_BASE}/v0/servers?search=${encodeURIComponent(name)}` }],
      };
    }
    return {
      ...base,
      status: 'warn',
      summary: 'Not found on the official MCP registry. Not disqualifying, but listed servers carry namespace-verified provenance.',
      evidence: [],
    };
  } catch (err) {
    return { ...base, status: 'unverifiable', summary: `Registry unreachable: ${errMsg(err)}`, evidence: [], degraded: true };
  }
}

export async function checkRepoHealth(ctx: CheckContext): Promise<CheckResult> {
  const base = {
    id: 'provenance.repo-health',
    policyRef: '§1.2',
    title: 'Source repository is public and maintained',
  };
  const gh = ctx.target.github;
  if (!gh) {
    return {
      ...base,
      status: 'warn',
      summary: 'No public source repository could be identified for this server.',
      evidence: [],
    };
  }

  try {
    const headers: Record<string, string> = {
      accept: 'application/vnd.github+json',
      'user-agent': 'mcpscorecard-scanner',
    };
    if (ctx.githubToken) headers.authorization = `Bearer ${ctx.githubToken}`;

    const repoRes = await fetchWithTimeout(ctx, `https://api.github.com/repos/${gh.owner}/${gh.repo}`, { headers });
    if (repoRes.status === 404) {
      // Only a repository the server actually claimed can be "missing". When we
      // guessed the coordinates from a directory slug, a 404 says nothing about
      // the server, only that our guess was wrong.
      if (ctx.target.githubInferred) {
        return {
          ...base,
          status: 'warn',
          summary: 'No public source repository could be identified for this server.',
          evidence: [],
        };
      }
      return { ...base, status: 'fail', summary: 'Claimed source repository does not exist (or is private).', evidence: [] };
    }
    if (!repoRes.ok) {
      // 401 means our token is missing, expired or revoked, and no amount of
      // retrying fixes it. 403/429 with the rate-limit budget exhausted is the
      // opposite: nothing is wrong with the repo, we simply ran out of quota.
      // Both are our problem rather than the server's, so neither may be scored
      // as a finding, but they need different operator responses.
      const credentialFailure = repoRes.status === 401;
      const rateLimited =
        (repoRes.status === 403 || repoRes.status === 429) &&
        repoRes.headers.get('x-ratelimit-remaining') === '0';
      const summary = credentialFailure
        ? 'GitHub rejected the scanner credentials (HTTP 401); repository health could not be checked.'
        : rateLimited
          ? 'GitHub rate limit exhausted (HTTP ' + repoRes.status + '); repository health could not be checked.'
          : `GitHub API error (HTTP ${repoRes.status}).`;
      return { ...base, status: 'unverifiable', summary, evidence: [], degraded: true, credentialFailure };
    }
    const repo = (await repoRes.json()) as {
      archived: boolean;
      pushed_at: string;
      stargazers_count: number;
      license: { spdx_id?: string } | null;
      html_url: string;
    };

    // SECURITY.md via the community-profile endpoint (covers root, .github/, docs/)
    let hasSecurityPolicy = false;
    const profileRes = await fetchWithTimeout(
      ctx,
      `https://api.github.com/repos/${gh.owner}/${gh.repo}/community/profile`,
      { headers },
    );
    if (profileRes.ok) {
      const profile = (await profileRes.json()) as { files?: { security?: unknown } };
      hasSecurityPolicy = Boolean(profile.files?.security);
    }

    const pushedDaysAgo = Math.floor((Date.now() - Date.parse(repo.pushed_at)) / 86_400_000);
    const evidence: Evidence[] = [
      { label: 'Repository', url: repo.html_url },
      { label: 'Last push', value: `${pushedDaysAgo} days ago` },
      { label: 'Stars', value: String(repo.stargazers_count) },
      { label: 'License', value: repo.license?.spdx_id ?? 'none detected' },
      { label: 'Security policy (SECURITY.md)', value: hasSecurityPolicy ? 'present' : 'absent' },
    ];

    if (repo.archived) {
      return { ...base, status: 'fail', summary: 'Repository is archived - unmaintained by declaration.', evidence };
    }
    // Maintenance signals, and the only things that can lower this check. Two
    // together is a fail, one is a warn.
    //
    // A published SECURITY.md is treated as a bonus, never a problem: almost no
    // small open-source repo has one, so requiring it made this check impossible
    // to pass (0 of 373 servers in the 2026-07-25 corpus) and therefore useless
    // for telling maintained repositories apart from neglected ones. Its presence
    // is reported as a positive signal; its absence costs nothing.
    const problems: string[] = [];
    if (pushedDaysAgo > STALE_PUSH_DAYS) problems.push(`no pushes in ${pushedDaysAgo} days`);
    if (!repo.license) problems.push('no license');

    if (problems.length === 0) {
      return {
        ...base,
        status: 'pass',
        summary: hasSecurityPolicy
          ? 'Active repository with a license and a published security policy.'
          : 'Active repository with a license.',
        evidence,
      };
    }
    return {
      ...base,
      status: problems.length >= 2 ? 'fail' : 'warn',
      summary: `Repository health issues: ${problems.join(', ')}.`,
      evidence,
    };
  } catch (err) {
    return { ...base, status: 'unverifiable', summary: `GitHub unreachable: ${errMsg(err)}`, evidence: [], degraded: true };
  }
}

/** Exported for testing. */
export function matchesTarget(server: Record<string, unknown>, ctx: CheckContext): boolean {
  const name = String(server['name'] ?? '').toLowerCase();
  const { registryName, npmPackage, pypiPackage, github } = ctx.target;
  if (registryName && name === registryName.toLowerCase()) return true;
  if (github && name.includes(`${github.owner.toLowerCase()}/${github.repo.toLowerCase()}`)) return true;
  const packages = (server['packages'] as Array<Record<string, unknown>> | undefined) ?? [];
  if (npmPackage) {
    const hit = packages.some(
      (p) =>
        String(p['registryType'] ?? p['registry_type'] ?? '') === 'npm' &&
        String(p['identifier'] ?? p['name'] ?? '').toLowerCase() === npmPackage.toLowerCase(),
    );
    if (hit) return true;
  }
  if (pypiPackage) {
    return packages.some(
      (p) =>
        String(p['registryType'] ?? p['registry_type'] ?? '').toLowerCase() === 'pypi' &&
        String(p['identifier'] ?? p['name'] ?? '').toLowerCase() === pypiPackage.toLowerCase(),
    );
  }
  return false;
}


