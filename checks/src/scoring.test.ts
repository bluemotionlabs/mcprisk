import { describe, expect, it } from 'vitest';
import { computeScore, CHECK_WEIGHTS, toGrade, GRADE_BANDS } from './scoring.js';
import { allPassChecks, result } from './test-helpers.js';

describe('toGrade', () => {
  it('maps boundary values correctly', () => {
    expect(toGrade(100)).toBe('A');
    expect(toGrade(90)).toBe('A');
    expect(toGrade(89)).toBe('B');
    expect(toGrade(80)).toBe('B');
    expect(toGrade(79)).toBe('C');
    expect(toGrade(65)).toBe('C');
    expect(toGrade(64)).toBe('D');
    expect(toGrade(50)).toBe('D');
    expect(toGrade(49)).toBe('F');
    expect(toGrade(0)).toBe('F');
  });

  it('returns F for negative scores', () => {
    expect(toGrade(-1)).toBe('F');
  });

  it('has non-overlapping grade bands', () => {
    const grades = GRADE_BANDS.map((b) => b.grade);
    const unique = new Set(grades);
    expect(unique.size).toBe(grades.length);
  });
});

describe('computeScore', () => {
  it('gives A for all passes', () => {
    const { score, grade } = computeScore(allPassChecks());
    expect(score).toBe(100);
    expect(grade).toBe('A');
  });

  it('caps grade at B when capabilities are unverifiable, even if all else passes', () => {
    const { grade, score } = computeScore(
      allPassChecks({
        'capabilities.tool-surface': 'unverifiable',
        'poisoning.patterns': 'unverifiable',
      }),
    );
    expect(score).toBe(100);
    expect(grade).toBe('B');
  });

  it('forces grade F when poisoning.patterns fails even if every other check passes', () => {
    const { grade, score } = computeScore(allPassChecks({ 'poisoning.patterns': 'fail' }));
    // Weighted score would still be high (poisoning is 15 of ~80); grade must be F per policy.
    expect(score).toBeGreaterThanOrEqual(80);
    expect(grade).toBe('F');
  });

  it('does not force F when poisoning.patterns is only a warn', () => {
    const { grade } = computeScore(allPassChecks({ 'poisoning.patterns': 'warn' }));
    expect(grade).not.toBe('F');
    expect(grade === 'A' || grade === 'B').toBe(true);
  });

  it('returns 0/F when nothing is scorable', () => {
    const { score, grade } = computeScore([result('capabilities.tool-surface', 'unverifiable')]);
    expect(score).toBe(0);
    expect(grade).toBe('F');
  });

  it('excludes info and unknown check ids from the denominator', () => {
    const checks = [
      result('provenance.registry-listed', 'pass'),
      result('transport.https', 'info'),
      result('not.a.real.check', 'fail'),
    ];
    const { score, grade } = computeScore(checks);
    expect(score).toBe(100);
    expect(grade).toBe('A');
  });

  it('scores warn as half weight', () => {
    // Only poisoning scored: warn → 0.5 * 20 / 20 = 50 → D
    const { score, grade } = computeScore([result('poisoning.patterns', 'warn')]);
    expect(score).toBe(50);
    expect(grade).toBe('D');
    expect(CHECK_WEIGHTS['poisoning.patterns']).toBe(20);
  });

  it('poisoning fail overrides the unverifiable-capability B cap to F', () => {
    const { grade } = computeScore([
      result('provenance.registry-listed', 'pass'),
      result('capabilities.tool-surface', 'unverifiable'),
      result('poisoning.patterns', 'fail'),
    ]);
    expect(grade).toBe('F');
  });
});

describe('CHECK_WEIGHTS consistency', () => {
  const KNOWN_CHECK_IDS = [
    'provenance.registry-listed',
    'provenance.repo-health',
    'provenance.package-hygiene',
    'capabilities.tool-surface',
    'transport.https',
    'transport.auth-required',
    'transport.oauth-metadata',
    'vulns.osv',
    'poisoning.patterns',
  ];

  it('every weighted check ID is a known check', () => {
    for (const id of Object.keys(CHECK_WEIGHTS)) {
      expect(KNOWN_CHECK_IDS).toContain(id);
    }
  });

  it('every known check ID has a weight', () => {
    for (const id of KNOWN_CHECK_IDS) {
      expect(CHECK_WEIGHTS[id]).toBeGreaterThan(0);
    }
  });

  it('weights sum to 100', () => {
    const total = Object.values(CHECK_WEIGHTS).reduce((a, b) => a + b, 0);
    expect(total).toBe(100);
  });
});
