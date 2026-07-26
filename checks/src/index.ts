/**
 * @mcpscorecard/checks - the open scoring model.
 *
 * runChecks() is the whole pipeline: resolve nothing, execute every
 * applicable check against an already-resolved ScanTarget, score the
 * results. Input resolution, persistence, and presentation live in the
 * application; everything that decides a score lives here, in the open.
 */

import type { CheckContext, CheckResult, ScanReport } from './types.js';
import { checkRegistryListed, checkRepoHealth } from './checks/provenance.js';
import { checkPackageHygiene } from './checks/package-hygiene.js';
import { checkVulnerabilities } from './checks/vulnerabilities.js';
import { checkTransport } from './checks/transport.js';
import { checkCapabilities, computeToolSchemaHash, getToolSurface } from './checks/capabilities.js';
import { checkPoisoning } from './checks/poisoning.js';
import { computeCapabilityRisk, computeScore } from './scoring.js';

export async function runChecks(ctx: CheckContext): Promise<ScanReport> {
  // Tool surface first so §3.2 can gate anonymous-auth severity on capability status.
  const surface = await getToolSurface(ctx);
  const capability = checkCapabilities(surface);
  // §3.2 gates anonymous-access severity on what the server can DO, so the
  // risk axis has to be resolved before the transport probe runs.
  const capabilityRisk = computeCapabilityRisk([capability]);

  const [registryListed, repoHealth, packageHygiene, vulns, transport] = await Promise.all([
    checkRegistryListed(ctx),
    checkRepoHealth(ctx),
    checkPackageHygiene(ctx),
    checkVulnerabilities(ctx),
    checkTransport(ctx, capabilityRisk),
  ]);

  const checks: CheckResult[] = [
    registryListed,
    repoHealth,
    packageHygiene,
    capability,
    ...transport,
    vulns,
    checkPoisoning(surface, ctx.target),
  ];

  const { score, grade } = computeScore(checks);
  const hasRealTools = surface.source === 'remote-tools-list' && surface.tools.length > 0;

  return {
    target: ctx.target,
    checks,
    score,
    grade,
    toolSchemaHash: hasRealTools ? await computeToolSchemaHash(surface.tools) : undefined,
    tools: hasRealTools ? surface.tools : undefined,
    toolSource: surface.source,
    capabilityRisk,
    createdAt: new Date().toISOString(),
  };
}

export * from './types.js';
export { assessScanQuality, type ScanQuality } from './quality.js';
export {
  computeScore,
  computeCapabilityRisk,
  capabilityRiskAtLeast,
  CAPABILITY_EVIDENCE_LABEL,
  CHECK_WEIGHTS,
  GRADE_BANDS,
  UNVERIFIABLE_CAPABILITY_CAP,
  POISONING_FAIL_GRADE,
} from './scoring.js';
export { POISON_PATTERNS, checkPoisoning } from './checks/poisoning.js';
export { RISK_PATTERNS, checkCapabilities, computeToolSchemaHash, getToolSurface } from './checks/capabilities.js';
export { checkRegistryListed, checkRepoHealth } from './checks/provenance.js';
export { checkPackageHygiene } from './checks/package-hygiene.js';
export { checkVulnerabilities } from './checks/vulnerabilities.js';
export { checkTransport, resolveAuthRequiredStatus } from './checks/transport.js';
