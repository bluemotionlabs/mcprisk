/**
 * §3 Authentication & transport hardening - remote servers only.
 *
 * Since the 2025-06-18 spec revision, remote MCP servers are OAuth 2.1
 * resource servers. We check three structural facts, cheapest first:
 * HTTPS (§3.1), auth actually demanded (§3.2), and protected-resource
 * metadata published (§3.3). Local stdio servers get 'info' - they run with
 * host privileges by design, which is §1/§2's problem, not §3's.
 *
 * §3.2 severity is gated on the server's Capability Risk (Policy §2 matrix):
 * anonymous access to a Low-rated surface is warn; anonymous access at Medium
 * or higher, or where capabilities could not be inspected, is fail.
 */

import type { CheckContext, CheckResult, CheckStatus } from '../types.js';
import type { CapabilityRisk } from '../scoring.js';
import { errMsg, fetchWithTimeout } from '../utils.js';

/** Auth probe outcome before capability gating is applied. */
export type AuthProbeOutcome =
  | 'required-with-www-auth'
  | 'required-no-www-auth'
  | 'anonymous'
  | 'unverifiable';

/**
 * Resolve §3.2 status from the auth probe and the server's capability risk.
 *
 * Gating on risk rather than on the §2 check status is what §3.2 actually
 * says: anonymous access to a Low-rated surface is a warn, anonymous access at
 * Medium or higher is failed outright, and an unauthenticated server whose
 * capabilities cannot be inspected takes the stricter branch, since the
 * public-read-only exception is a claim the server has to be able to show.
 *
 * Pure helper so tests do not need network.
 */
export function resolveAuthRequiredStatus(
  authOutcome: AuthProbeOutcome,
  capabilityRisk: CapabilityRisk = 'low',
): CheckStatus {
  if (authOutcome === 'required-with-www-auth') return 'pass';
  if (authOutcome === 'required-no-www-auth') return 'warn';
  if (authOutcome === 'unverifiable') return 'unverifiable';
  return capabilityRisk === 'low' ? 'warn' : 'fail';
}

function authSummary(outcome: AuthProbeOutcome, status: CheckStatus, httpStatus?: number): string {
  if (outcome === 'required-with-www-auth') {
    return 'Server rejects anonymous requests and advertises its auth scheme.';
  }
  if (outcome === 'required-no-www-auth') {
    return 'Server rejects anonymous requests but sends no WWW-Authenticate header.';
  }
  if (outcome === 'unverifiable') {
    if (httpStatus === undefined) return 'Endpoint unreachable during auth probe.';
    if (httpStatus >= 500) {
      return `Endpoint returned a server error (HTTP ${httpStatus}); whether it requires authentication could not be determined.`;
    }
    if (httpStatus === 404 || httpStatus === 405) {
      return `No MCP endpoint responded at this URL (HTTP ${httpStatus}); authentication could not be probed.`;
    }
    return `Endpoint rejected the probe (HTTP ${httpStatus}); whether it requires authentication could not be determined.`;
  }
  if (status === 'fail') {
    return `Server answers anonymous requests (HTTP ${httpStatus}) while exposing non-trivial or unverifiable capabilities - fail per §3.2.`;
  }
  return `Server answers anonymous requests (HTTP ${httpStatus}). Acceptable only for deliberately public, read-only (Low) servers.`;
}

export async function checkTransport(
  ctx: CheckContext,
  capabilityRisk: CapabilityRisk = 'low',
): Promise<CheckResult[]> {
  const url = ctx.target.remoteUrl;
  if (!url) {
    return [
      {
        id: 'transport.https',
        policyRef: '§3',
        title: 'Transport & authentication',
        status: 'info',
        summary:
          'Local (stdio) server: runs with host-process privileges by design. Transport checks apply to remote servers; scrutiny shifts to §1/§2.',
        evidence: [],
      },
    ];
  }

  const results: CheckResult[] = [];
  const parsed = new URL(url);

  results.push({
    id: 'transport.https',
    policyRef: '§3.1',
    title: 'HTTPS-only endpoint',
    status: parsed.protocol === 'https:' ? 'pass' : 'fail',
    summary:
      parsed.protocol === 'https:'
        ? 'Endpoint uses HTTPS.'
        : 'Endpoint is plain HTTP - credentials and tool traffic are exposed.',
    evidence: [{ label: 'Endpoint', value: url }],
  });

  // §3.2 - does the server demand auth for an unauthenticated MCP request?
  try {
    const res = await fetchWithTimeout(ctx, url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json, text/event-stream',
      },
      body: JSON.stringify({ jsonrpc: '2.0', id: 0, method: 'ping' }),
    });
    const wwwAuth = res.headers.get('www-authenticate');
    let outcome: AuthProbeOutcome;
    let evidence: CheckResult['evidence'] = [];

    // Only a substantive response proves the server served us without
    // credentials. A gateway error or a missing route proves nothing either way,
    // and reporting it as "answers anonymous requests while exposing
    // capabilities" asserts something the response does not support.
    let degraded = false;
    if (res.status === 401 || res.status === 403) {
      outcome = wwwAuth ? 'required-with-www-auth' : 'required-no-www-auth';
      evidence = wwwAuth ? [{ label: 'WWW-Authenticate', value: wwwAuth }] : [];
    } else if (res.ok) {
      outcome = 'anonymous';
    } else {
      outcome = 'unverifiable';
      // 5xx is the origin failing, which is transient often enough to retry.
      degraded = res.status >= 500;
    }

    const status = resolveAuthRequiredStatus(outcome, capabilityRisk);
    results.push({
      id: 'transport.auth-required',
      policyRef: '§3.2',
      title: 'Authentication required',
      status,
      summary: authSummary(outcome, status, res.status),
      evidence,
      degraded: degraded || undefined,
    });
  } catch (err) {
    results.push({
      id: 'transport.auth-required',
      policyRef: '§3.2',
      title: 'Authentication required',
      status: 'unverifiable',
      summary: `Endpoint unreachable: ${errMsg(err)}`,
      evidence: [],
    });
  }

  // §3.3 - OAuth 2.1 protected-resource metadata (RFC 9728)
  try {
    const wellKnown = `${parsed.origin}/.well-known/oauth-protected-resource`;
    const res = await fetchWithTimeout(ctx, wellKnown);
    if (res.ok) {
      const body = (await res.json()) as { authorization_servers?: string[] };
      results.push({
        id: 'transport.oauth-metadata',
        policyRef: '§3.3',
        title: 'OAuth protected-resource metadata published',
        status: 'pass',
        summary: 'Publishes /.well-known/oauth-protected-resource per the June 2025 authorization spec.',
        evidence: (body.authorization_servers ?? []).map((as) => ({
          label: 'Authorization server',
          value: as,
        })),
      });
    } else {
      results.push({
        id: 'transport.oauth-metadata',
        policyRef: '§3.3',
        title: 'OAuth protected-resource metadata published',
        status: 'warn',
        summary:
          'No protected-resource metadata found - clients cannot discover the authorization server per spec.',
        evidence: [{ label: 'Checked', value: wellKnown }],
      });
    }
  } catch (err) {
    results.push({
      id: 'transport.oauth-metadata',
      policyRef: '§3.3',
      title: 'OAuth protected-resource metadata published',
      status: 'unverifiable',
      summary: `Metadata endpoint unreachable: ${errMsg(err)}`,
      evidence: [],
    });
  }

  return results;
}
