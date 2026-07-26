/**
 * Scan quality assessment: is this report fit to publish as a grade?
 *
 * The scoring model treats unverifiability as a finding, which is a deliberate
 * policy position (§2). That position only holds when the unverifiability is a
 * fact about the SERVER. When it is a fact about the scanner (GitHub rate
 * limit, registry timeout, expired token), publishing the grade states
 * something false: the 2026-07-25 corpus graded the official
 * modelcontextprotocol reference servers F for exactly this reason.
 *
 * So the queue asks two questions before writing a scan: did anything we depend
 * on fail, and did we manage to observe anything at all.
 */

import type { CheckResult, ScanReport } from './types.js';

export interface ScanQuality {
  /** Check ids whose result was caused by an upstream failure on our side. */
  degradedChecks: string[];
  /** An upstream rejected our credentials; retrying will not help. */
  credentialFailure: boolean;
  /**
   * No check reached a real verdict: every result is unverifiable or not
   * applicable. A grade computed from this describes the scan, not the server.
   */
  whollyUnobserved: boolean;
  /** True when the report is safe to persist as this server's current grade. */
  publishable: boolean;
}

const VERDICT_STATUSES = new Set(['pass', 'warn', 'fail']);

export function assessScanQuality(report: Pick<ScanReport, 'checks'>): ScanQuality {
  const checks: CheckResult[] = report.checks ?? [];
  const degradedChecks = checks.filter((c) => c.degraded).map((c) => c.id);
  const credentialFailure = checks.some((c) => c.credentialFailure);
  // An empty check list is the degenerate case of observing nothing.
  const whollyUnobserved = checks.length === 0 || !checks.some((c) => VERDICT_STATUSES.has(c.status));

  return {
    degradedChecks,
    credentialFailure,
    whollyUnobserved,
    publishable: degradedChecks.length === 0 && !whollyUnobserved,
  };
}
