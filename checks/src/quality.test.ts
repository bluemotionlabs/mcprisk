import { describe, expect, it } from 'vitest';
import { assessScanQuality } from './quality.js';
import type { CheckResult } from './types.js';

const check = (over: Partial<CheckResult>): CheckResult => ({
  id: 'x',
  policyRef: '§0',
  title: 't',
  status: 'pass',
  summary: '',
  evidence: [],
  ...over,
});

describe('assessScanQuality', () => {
  it('publishes a scan where every check reached a verdict', () => {
    const q = assessScanQuality({
      checks: [check({ id: 'a', status: 'pass' }), check({ id: 'b', status: 'fail' })],
    });
    expect(q.publishable).toBe(true);
    expect(q.degradedChecks).toEqual([]);
    expect(q.whollyUnobserved).toBe(false);
  });

  it('publishes when unverifiability is a fact about the server', () => {
    // "No reachable tools/list, no public package source" is a finding, not an outage.
    const q = assessScanQuality({
      checks: [check({ id: 'a', status: 'pass' }), check({ id: 'b', status: 'unverifiable' })],
    });
    expect(q.publishable).toBe(true);
  });

  it('withholds a scan when one of our upstreams failed', () => {
    const q = assessScanQuality({
      checks: [
        check({ id: 'provenance.repo-health', status: 'unverifiable', degraded: true }),
        check({ id: 'transport.https', status: 'pass' }),
      ],
    });
    expect(q.publishable).toBe(false);
    expect(q.degradedChecks).toEqual(['provenance.repo-health']);
  });

  it('withholds a scan where nothing at all was observed', () => {
    // The 2026-07-25 score-0 rows: every check unverifiable, graded F anyway.
    const q = assessScanQuality({
      checks: [
        check({ id: 'a', status: 'unverifiable' }),
        check({ id: 'b', status: 'unverifiable' }),
        check({ id: 'c', status: 'info' }),
      ],
    });
    expect(q.whollyUnobserved).toBe(true);
    expect(q.publishable).toBe(false);
  });

  it('withholds a scan that produced no checks at all', () => {
    // github:larebelion/hapimcp was stored as score 0 / grade F with checks: [].
    const q = assessScanQuality({ checks: [] });
    expect(q.whollyUnobserved).toBe(true);
    expect(q.publishable).toBe(false);
  });

  it('flags a credential failure separately from a rate limit', () => {
    const q = assessScanQuality({
      checks: [check({ id: 'provenance.repo-health', status: 'unverifiable', degraded: true, credentialFailure: true })],
    });
    expect(q.credentialFailure).toBe(true);
    expect(q.publishable).toBe(false);
  });

  it('does not report a credential failure for an ordinary degraded scan', () => {
    const q = assessScanQuality({
      checks: [check({ id: 'a', status: 'pass' }), check({ id: 'b', status: 'unverifiable', degraded: true })],
    });
    expect(q.credentialFailure).toBe(false);
  });
});
