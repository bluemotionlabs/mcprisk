/**
 * §1.3 Package integrity - npm / PyPI registry signals.
 *
 * Typosquatting an MCP server yields agent-level access, so the package
 * itself is scrutinized: does it match its claimed repo, is it maintained,
 * does its age/download history fit its claimed role, and does it carry a
 * build-provenance attestation where the ecosystem supports it?
 */

import type { CheckContext, CheckResult, Evidence } from '../types.js';
import { errMsg, fetchWithTimeout } from '../utils.js';

const YOUNG_PACKAGE_DAYS = 30;

export async function checkPackageHygiene(ctx: CheckContext): Promise<CheckResult> {
  const base = {
    id: 'provenance.package-hygiene',
    policyRef: '§1.3',
    title: 'Published package is consistent and attested',
  };

  if (ctx.target.npmPackage) {
    return checkNpmHygiene(ctx, base, ctx.target.npmPackage);
  }
  if (ctx.target.pypiPackage) {
    return checkPypiHygiene(ctx, base, ctx.target.pypiPackage);
  }

  return {
    ...base,
    status: 'info',
    summary: 'No published package associated with this server (remote-only or non-npm/PyPI source).',
    evidence: [],
  };
}

type HygieneBase = {
  id: string;
  policyRef: string;
  title: string;
};

async function checkNpmHygiene(ctx: CheckContext, base: HygieneBase, pkg: string): Promise<CheckResult> {
  try {
    const res = await fetchWithTimeout(ctx, `https://registry.npmjs.org/${encodeURIComponent(pkg)}`);
    if (res.status === 404) {
      return { ...base, status: 'fail', summary: `Package "${pkg}" does not exist on npm.`, evidence: [] };
    }
    if (!res.ok) {
      return { ...base, status: 'unverifiable', summary: `npm registry error (HTTP ${res.status}).`, evidence: [], degraded: true };
    }
    const meta = (await res.json()) as {
      'dist-tags'?: Record<string, string>;
      time?: Record<string, string>;
      versions?: Record<
        string,
        { deprecated?: string; repository?: { url?: string }; dist?: { attestations?: unknown } }
      >;
      repository?: { url?: string };
    };

    const latest = meta['dist-tags']?.latest;
    const latestMeta = latest ? meta.versions?.[latest] : undefined;
    const created = meta.time?.created ? Date.parse(meta.time.created) : undefined;
    const ageDays = created ? Math.floor((Date.now() - created) / 86_400_000) : undefined;

    let weeklyDownloads: number | undefined;
    try {
      const dl = await fetchWithTimeout(
        ctx,
        `https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(pkg)}`,
      );
      if (dl.ok) weeklyDownloads = ((await dl.json()) as { downloads?: number }).downloads;
    } catch {
      // downloads API is best-effort
    }

    const repoUrl = (latestMeta?.repository?.url ?? meta.repository?.url ?? '').toLowerCase();
    const gh = ctx.target.github;
    const repoMatches = gh ? repoUrl.includes(`${gh.owner.toLowerCase()}/${gh.repo.toLowerCase()}`) : undefined;
    const hasAttestation = Boolean(latestMeta?.dist?.attestations);
    const deprecated = Boolean(latestMeta?.deprecated);

    const evidence: Evidence[] = [
      { label: 'Package', value: `${pkg}@${latest ?? '?'}`, url: `https://www.npmjs.com/package/${pkg}` },
      { label: 'Ecosystem', value: 'npm' },
      { label: 'Age', value: ageDays !== undefined ? `${ageDays} days` : 'unknown' },
      { label: 'Weekly downloads', value: weeklyDownloads !== undefined ? String(weeklyDownloads) : 'unknown' },
      { label: 'Repo field matches source repo', value: repoMatches === undefined ? 'n/a' : String(repoMatches) },
      { label: 'Build-provenance attestation', value: hasAttestation ? 'present' : 'absent' },
    ];

    return finalizeHygiene(base, evidence, {
      deprecated,
      repoMatches,
      ageDays,
      hasAttestation,
      attestationLabel: 'no npm provenance attestation',
    });
  } catch (err) {
    return { ...base, status: 'unverifiable', summary: `npm registry unreachable: ${errMsg(err)}`, evidence: [], degraded: true };
  }
}

async function checkPypiHygiene(ctx: CheckContext, base: HygieneBase, pkg: string): Promise<CheckResult> {
  try {
    const res = await fetchWithTimeout(ctx, `https://pypi.org/pypi/${encodeURIComponent(pkg)}/json`);
    if (res.status === 404) {
      return { ...base, status: 'fail', summary: `Package "${pkg}" does not exist on PyPI.`, evidence: [] };
    }
    if (!res.ok) {
      return { ...base, status: 'unverifiable', summary: `PyPI error (HTTP ${res.status}).`, evidence: [], degraded: true };
    }
    const meta = (await res.json()) as {
      info?: {
        name?: string;
        version?: string;
        yanked?: boolean;
        home_page?: string | null;
        project_urls?: Record<string, string> | null;
        package_url?: string;
      };
      urls?: Array<{ packagetype?: string; url?: string; size?: number; yanked?: boolean }>;
      releases?: Record<string, Array<{ upload_time_iso_8601?: string; upload_time?: string }>>;
    };

    const info = meta.info ?? {};
    const latest = info.version;
    const yanked = Boolean(info.yanked);
    const repoBlob = [
      info.home_page ?? '',
      ...Object.values(info.project_urls ?? {}),
    ]
      .join(' ')
      .toLowerCase();
    const gh = ctx.target.github;
    const repoMatches = gh
      ? repoBlob.includes(`${gh.owner.toLowerCase()}/${gh.repo.toLowerCase()}`)
      : undefined;

    let ageDays: number | undefined;
    const times: number[] = [];
    for (const files of Object.values(meta.releases ?? {})) {
      for (const f of files) {
        const raw = f.upload_time_iso_8601 ?? f.upload_time;
        if (raw) {
          const t = Date.parse(raw);
          if (!Number.isNaN(t)) times.push(t);
        }
      }
    }
    if (times.length) {
      ageDays = Math.floor((Date.now() - Math.min(...times)) / 86_400_000);
    }

    let hasAttestation = false;
    if (latest) {
      try {
        const prov = await fetchWithTimeout(
          ctx,
          `https://pypi.org/integrity/${encodeURIComponent(pkg)}/${encodeURIComponent(latest)}/provenance`,
        );
        hasAttestation = prov.ok;
      } catch {
        // provenance lookup is best-effort
      }
    }

    const evidence: Evidence[] = [
      {
        label: 'Package',
        value: `${pkg}@${latest ?? '?'}`,
        url: `https://pypi.org/project/${encodeURIComponent(pkg)}/`,
      },
      { label: 'Ecosystem', value: 'PyPI' },
      { label: 'Age', value: ageDays !== undefined ? `${ageDays} days` : 'unknown' },
      { label: 'Repo field matches source repo', value: repoMatches === undefined ? 'n/a' : String(repoMatches) },
      { label: 'Trusted-publishing provenance', value: hasAttestation ? 'present' : 'absent' },
    ];

    return finalizeHygiene(base, evidence, {
      deprecated: yanked,
      repoMatches,
      ageDays,
      hasAttestation,
      attestationLabel: 'no PyPI trusted-publishing provenance',
      deprecatedSummary: 'Latest version is yanked on PyPI.',
    });
  } catch (err) {
    return { ...base, status: 'unverifiable', summary: `PyPI unreachable: ${errMsg(err)}`, evidence: [], degraded: true };
  }
}

function finalizeHygiene(
  base: HygieneBase,
  evidence: Evidence[],
  opts: {
    deprecated: boolean;
    repoMatches: boolean | undefined;
    ageDays: number | undefined;
    hasAttestation: boolean;
    attestationLabel: string;
    deprecatedSummary?: string;
  },
): CheckResult {
  if (opts.deprecated) {
    return {
      ...base,
      status: 'fail',
      summary: opts.deprecatedSummary ?? 'Latest version is deprecated by its own maintainer.',
      evidence,
    };
  }
  const warns: string[] = [];
  if (opts.repoMatches === false) warns.push('package repository field does not match the claimed source repo');
  if (opts.ageDays !== undefined && opts.ageDays < YOUNG_PACKAGE_DAYS) {
    warns.push(`package is only ${opts.ageDays} days old`);
  }
  if (!opts.hasAttestation) warns.push(opts.attestationLabel);

  if (opts.repoMatches === false && warns.length >= 2) {
    return { ...base, status: 'fail', summary: `Integrity concerns: ${warns.join('; ')}.`, evidence };
  }
  if (warns.length > 0) {
    return { ...base, status: 'warn', summary: `Minor integrity gaps: ${warns.join('; ')}.`, evidence };
  }
  return {
    ...base,
    status: 'pass',
    summary: 'Package is consistent with its source and carries provenance attestation.',
    evidence,
  };
}
