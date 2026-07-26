/**
 * Core types for the MCP server security scoring model.
 * Each CheckResult maps to a numbered section of the MCP Server Security Policy.
 */

export type CheckStatus = 'pass' | 'warn' | 'fail' | 'info' | 'unverifiable';

export type SourceType = 'npm' | 'pypi' | 'github' | 'registry' | 'remote';

export interface Evidence {
  label: string;
  value?: string;
  url?: string;
}

export interface CheckResult {
  /** Stable check identifier, e.g. "provenance.repo-health" */
  id: string;
  /** Policy section this check verifies, e.g. "§1.2" */
  policyRef: string;
  title: string;
  status: CheckStatus;
  /** One-line human summary of the outcome */
  summary: string;
  evidence: Evidence[];
  /**
   * The result is unverifiable because OUR dependency failed (GitHub rate limit,
   * registry timeout, OSV outage), not because the server offers nothing to
   * inspect. Those are different claims and must not be scored the same: the
   * first is a reason to retry, the second is a finding. Callers should treat a
   * degraded report as provisional rather than publishing a grade from it.
   */
  degraded?: boolean;
  /**
   * Set when the upstream rejected our credentials (HTTP 401). Distinct from a
   * rate limit because retrying cannot fix it; the token needs replacing.
   */
  credentialFailure?: boolean;
}

/** A scan target after input resolution, with whatever identifiers could be cross-resolved. */
export interface ScanTarget {
  input: string;
  sourceType: SourceType;
  displayName: string;
  npmPackage?: string;
  /** PyPI distribution name, e.g. "mcp" or "anthropic-mcp" */
  pypiPackage?: string;
  github?: { owner: string; repo: string };
  /**
   * The GitHub coordinates were GUESSED from a directory slug rather than
   * declared by the server. mcpservers.org lists monorepo-hosted servers under
   * names like "modelcontextprotocol/everything", which is not a repository.
   * A 404 on inferred coordinates means we could not find the source, not that
   * the server claimed a repository that does not exist, and §1.2 must not
   * report the stronger claim.
   */
  githubInferred?: boolean;
  /** Official-registry server name, e.g. "io.github.owner/server" */
  registryName?: string;
  remoteUrl?: string;
}

export interface ToolInfo {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

/** A named, model-facing text item (a prompt or resource entry) carrying a description. */
export interface NamedText {
  name: string;
  description?: string;
}

/** How the tool list was obtained; "none" means capabilities are unverifiable. */
export type ToolSource = 'remote-tools-list' | 'registry-metadata' | 'package-source' | 'none';

export interface ToolSurface {
  source: ToolSource;
  tools: ToolInfo[];
  /** Raw risk keywords found in package source when tools couldn't be enumerated directly */
  sourceRiskHits: RiskHit[];
  /** Remote server demanded auth before listing tools (a §3 pass, a §2 fallback) */
  remoteAuthRequired?: boolean;
  /** Server-provided `instructions` from the MCP initialize response; the spec
   * lets clients inject this into the system prompt, so it is scanned for
   * poisoning just like a tool description. */
  serverInstructions?: string;
  /**
   * A package registry or archive fetch failed, so "no inspectable source" is a
   * statement about the outage rather than about the server.
   */
  degraded?: boolean;
  /** Prompt entries (prompts/list); their names/descriptions are model-facing too. */
  prompts?: NamedText[];
  /** Resource entries (resources/list); names/descriptions scanned, URIs left alone. */
  resources?: NamedText[];
}

export interface RiskHit {
  category: RiskCategory;
  pattern: string;
  /** Human label for the matched pattern family */
  label?: string;
  file?: string;
  excerpt?: string;
}

export type RiskCategory =
  | 'process-execution'
  | 'filesystem'
  | 'network-egress'
  | 'credential-access';

export interface CheckContext {
  target: ScanTarget;
  fetch: typeof globalThis.fetch;
  /** GitHub token (public-repo read). Without it, repo checks degrade to unverifiable. */
  githubToken?: string;
  /** Per-request timeout in ms for outbound calls (default 10s) */
  timeoutMs?: number;
}

export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

import type { CapabilityRisk } from './scoring.js';
export type { CapabilityRisk };

export interface ScanReport {
  target: ScanTarget;
  checks: CheckResult[];
  score: number;
  grade: Grade;
  /** SHA-256 over canonicalized tool names+descriptions+input schemas; absent if no tools obtained */
  toolSchemaHash?: string;
  tools?: ToolInfo[];
  toolSource: ToolSource;
  /**
   * What the tools can do, reported alongside the trust grade rather than
   * folded into it. 'unknown' when the tool surface could not be inspected.
   */
  capabilityRisk: CapabilityRisk;
  createdAt: string;
}
