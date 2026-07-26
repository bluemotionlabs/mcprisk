/**
 * Scoring: fully public by design. A score you can't audit is a score you
 * shouldn't trust - weights, bands, and caps all live here, in the open.
 *
 * Model:
 *  - Each check earns points: pass = 1.0, warn = 0.5, fail = 0.
 *  - 'info' results are displayed but unscored.
 *  - 'unverifiable' results are excluded from the denominator, EXCEPT the
 *    capability check (§2): if the tool surface cannot be inspected at all,
 *    the overall grade is capped at B (Policy: "cannot verify is a finding").
 *  - A §5 (`poisoning.patterns`) fail forces the overall grade to F, regardless
 *    of every other section (Policy structural rule #2). The numeric score
 *    remains the weighted value for auditability; only the letter grade is overridden.
 *  - Check weights reflect policy-section importance (§2 capability scope
 *    dominates: what a server can do matters more than where it's listed).
 */

import type { CheckResult, Grade } from './types.js';

/**
 * Trust weights. `capabilities.tool-surface` scores INSPECTABILITY only (can an
 * outsider see what this server does), not capability breadth. What the tools
 * can actually do is the separate Capability Risk axis below, and carries no
 * grade penalty: a filesystem server is supposed to touch the filesystem, and
 * scoring that as a defect made the most useful class of server unable to grade
 * well no matter how honestly it was built (Policy §2.4).
 */
export const CHECK_WEIGHTS: Record<string, number> = {
  'provenance.registry-listed': 5,
  'provenance.repo-health': 12,
  'provenance.package-hygiene': 12,
  'capabilities.tool-surface': 15,
  'transport.https': 5,
  'transport.auth-required': 14,
  'transport.oauth-metadata': 5,
  'vulns.osv': 12,
  'poisoning.patterns': 20,
};

/**
 * What a server's tools can DO, independent of who wrote it. Reported alongside
 * the trust grade rather than folded into it. Levels follow the Capability Risk
 * Matrix in Policy §2.
 */
export type CapabilityRisk = 'low' | 'medium' | 'high' | 'critical' | 'unknown';

/**
 * The evidence label under which the capability check records what it detected.
 * Recording it as evidence (rather than passing it out of band) keeps a stored
 * scan self-describing, so the risk axis can be recomputed from a persisted
 * report without rescanning the server.
 */
export const CAPABILITY_EVIDENCE_LABEL = 'Detected capabilities';

const CAPABILITY_RISK_RANK: Record<CapabilityRisk, number> = {
  unknown: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function computeCapabilityRisk(checks: CheckResult[]): CapabilityRisk {
  const capability = checks.find((c) => c.id === 'capabilities.tool-surface');
  // Nothing inspected means nothing can be claimed about capability either way.
  if (!capability || capability.status === 'unverifiable') return 'unknown';

  const recorded = capability.evidence.find((e) => e.label === CAPABILITY_EVIDENCE_LABEL);
  const categories = new Set(
    (recorded?.value ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length > 0 && s !== 'none'),
  );

  if (categories.size === 0) return 'low';
  // Process execution subsumes every other capability (§2 matrix).
  if (categories.has('process-execution')) return 'critical';
  // Combination rule: reading credential material plus egress is an
  // exfiltration pipeline even when each half is individually acceptable.
  if (categories.has('credential-access') && categories.has('network-egress')) return 'critical';
  if (categories.has('filesystem') || categories.has('network-egress')) return 'high';
  if (categories.has('credential-access')) return 'medium';
  return 'low';
}

export function capabilityRiskAtLeast(risk: CapabilityRisk, floor: CapabilityRisk): boolean {
  return CAPABILITY_RISK_RANK[risk] >= CAPABILITY_RISK_RANK[floor];
}

export const GRADE_BANDS: Array<{ min: number; grade: Grade }> = [
  { min: 90, grade: 'A' },
  { min: 80, grade: 'B' },
  { min: 65, grade: 'C' },
  { min: 50, grade: 'D' },
  { min: 0, grade: 'F' },
];

/** Grade cap applied when the tool surface is unverifiable (Policy §2.1). */
export const UNVERIFIABLE_CAPABILITY_CAP: Grade = 'B';

/** Grade forced when instruction-integrity (§5) fails (Policy structural rule #2). */
export const POISONING_FAIL_GRADE: Grade = 'F';

const STATUS_POINTS: Record<string, number | null> = {
  pass: 1,
  warn: 0.5,
  fail: 0,
  info: null, // displayed, unscored
  unverifiable: null, // excluded from denominator (capability cap handled separately)
};

export function computeScore(checks: CheckResult[]): { score: number; grade: Grade } {
  let earned = 0;
  let possible = 0;

  for (const check of checks) {
    const weight = CHECK_WEIGHTS[check.id];
    if (weight === undefined) continue;
    const points = STATUS_POINTS[check.status];
    if (points === null || points === undefined) continue;
    earned += points * weight;
    possible += weight;
  }

  // No scorable checks at all → score 0/F rather than a divide-by-zero A.
  const score = possible === 0 ? 0 : Math.round((earned / possible) * 100);
  let grade = toGrade(score);

  const capabilityUnverifiable = checks.some(
    (c) => c.id === 'capabilities.tool-surface' && c.status === 'unverifiable',
  );
  if (capabilityUnverifiable && gradeRank(grade) < gradeRank(UNVERIFIABLE_CAPABILITY_CAP)) {
    grade = UNVERIFIABLE_CAPABILITY_CAP;
  }

  const poisoningFailed = checks.some((c) => c.id === 'poisoning.patterns' && c.status === 'fail');
  if (poisoningFailed) {
    grade = POISONING_FAIL_GRADE;
  }

  return { score, grade };
}

export function toGrade(score: number): Grade {
  for (const band of GRADE_BANDS) {
    if (score >= band.min) return band.grade;
  }
  return 'F';
}

/** Lower rank = better grade. */
function gradeRank(grade: Grade): number {
  return ['A', 'B', 'C', 'D', 'F'].indexOf(grade);
}
