/**
 * §2 Capability scope & least privilege - the core check.
 *
 * The tool surface is obtained WITHOUT ever executing untrusted code:
 *   1. Remote servers: a standard MCP initialize + tools/list over
 *      streamable HTTP. A 401 here is signal, not failure (feeds §3.2).
 *   2. npm / PyPI packages: the published archive is fetched (size-capped,
 *      streamed, never executed) and statically scanned for risk-bearing
 *      capabilities and description strings.
 * If neither source yields anything, the result is 'unverifiable' - which
 * the scoring model treats as a finding (grade cap), not a blank.
 */

import type {
  CheckContext,
  CheckResult,
  Evidence,
  NamedText,
  RiskCategory,
  RiskHit,
  ToolInfo,
  ToolSurface,
} from '../types.js';
import { errMsg, fetchWithTimeout } from '../utils.js';
import { CAPABILITY_EVIDENCE_LABEL } from '../scoring.js';

const TARBALL_MAX_BYTES = 10 * 1024 * 1024;
const MAX_SCANNED_FILES = 400;
const SOURCE_FILE_RE = /\.(m?[jt]s|cjs|py)$/;

/** Capability patterns scanned in package source. Public by design. */
export const RISK_PATTERNS: Array<{ category: RiskCategory; label: string; regex: RegExp }> = [
  { category: 'process-execution', label: 'child process execution', regex: /\b(child_process|execSync|execFile|spawnSync?|subprocess\.(run|Popen|call)|os\.system)\b/ },
  { category: 'process-execution', label: 'child process module import', regex: /\b(?:import\s.*\bfrom\s*|require\s*\()['"](?:node:)?child_process['"]/ },
  { category: 'process-execution', label: 'dynamic code evaluation', regex: /\b(eval|new Function|vm\.runInNewContext)\s*\(/ },
  { category: 'process-execution', label: 'vm module import', regex: /\b(?:import\s.*\bfrom\s*|require\s*\()['"](?:node:)?vm['"]/ },
  { category: 'filesystem', label: 'filesystem write/delete', regex: /\bfs(?:\/promises)?[.'"]|\b(writeFileSync?|unlinkSync?|rmSync|rmdirSync?|shutil\.rmtree|os\.remove)\b/ },
  { category: 'filesystem', label: 'fs module import', regex: /\b(?:import\s.*\bfrom\s*|require\s*\()['"](?:node:)?fs(?:\/promises)?['"]/ },
  { category: 'network-egress', label: 'outbound network calls', regex: /\b(fetch\s*\(|axios|got\s*\(|node:https?|http\.request|requests\.(get|post)|urllib)\b/ },
  { category: 'network-egress', label: 'http module import', regex: /\b(?:import\s.*\bfrom\s*|require\s*\()['"](?:node:)?https?['"]/ },
  { category: 'credential-access', label: 'credential/env access', regex: /\b(process\.env|os\.environ)\s*[.[][^\s\]]*\b(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH)/i },
];

/**
 * Categories inferred from tool names and descriptions, used when a live
 * tools/list is all we have.
 *
 * Two categories are constrained here, because prose cannot establish what code
 * does and both were producing Critical ratings for servers that do neither.
 *
 * - credential-access is absent entirely. A description mentioning "api key" or
 *   "token" is almost always documenting the tool's own auth requirement, which
 *   every authenticated tool does.
 * - process-execution matches the tool NAME only, not its description. A tool
 *   called `run_shell` is declaring what it does; "the command you previously
 *   started" in a description is ordinary English. Matching descriptions
 *   labelled get_scan_status, search_docs and query_registry as shell
 *   execution, and since process-execution alone escalates to Critical, that
 *   put the loudest badge available on read-only lookup tools.
 *
 * Both are still read from package source, where `child_process` or
 * `process.env.X_TOKEN` is direct evidence rather than prose.
 */
const TOOL_TEXT_RISKS: Array<{ category: RiskCategory; regex: RegExp; scope?: 'name' }> = [
  { category: 'process-execution', regex: /\b(shell|exec|command|terminal|bash|run[_ ]?(command|script))\b/i, scope: 'name' },
  { category: 'filesystem', regex: /\b(delete|remove|write|overwrite|move)[_ ]?(file|directory|folder|path)|filesystem\b/i },
  { category: 'network-egress', regex: /\b(http[_ ]?request|fetch[_ ]?url|curl|webhook|send[_ ]?request)\b/i },
];

/**
 * A package registry or archive fetch failed for a reason that is not "the
 * package does not exist". `transient` separates an outage worth retrying from
 * a genuine 404, so a bad npm day cannot be reported as "no public source".
 */
class UpstreamUnavailable extends Error {
  readonly transient: boolean;
  constructor(detail?: string) {
    super(detail ?? 'package not published');
    this.name = 'UpstreamUnavailable';
    this.transient = detail !== undefined;
  }
}

export async function getToolSurface(ctx: CheckContext): Promise<ToolSurface> {
  const surface: ToolSurface = { source: 'none', tools: [], sourceRiskHits: [] };

  if (ctx.target.remoteUrl) {
    const remote = await tryRemoteToolsList(ctx, ctx.target.remoteUrl);
    if (remote.authRequired) surface.remoteAuthRequired = true;
    if (remote.instructions) surface.serverInstructions = remote.instructions;
    if (remote.prompts?.length) surface.prompts = remote.prompts;
    if (remote.resources?.length) surface.resources = remote.resources;
    if (remote.tools) {
      surface.source = 'remote-tools-list';
      surface.tools = remote.tools;
      return surface;
    }
  }

  // TODO(v1.1): try directory metadata (some directories index tool lists).

  if (ctx.target.npmPackage) {
    try {
      const pkgScan = await tryNpmTarballScan(ctx, ctx.target.npmPackage);
      if (pkgScan) {
        surface.source = 'package-source';
        surface.tools = pkgScan.descriptionTools;
        surface.sourceRiskHits = pkgScan.hits;
        return surface;
      }
    } catch (err) {
      if (err instanceof UpstreamUnavailable && err.transient) surface.degraded = true;
    }
  }

  if (ctx.target.pypiPackage) {
    try {
      const pkgScan = await tryPypiSdistScan(ctx, ctx.target.pypiPackage);
      if (pkgScan) {
        surface.source = 'package-source';
        surface.tools = pkgScan.descriptionTools;
        surface.sourceRiskHits = pkgScan.hits;
        return surface;
      }
    } catch (err) {
      if (err instanceof UpstreamUnavailable && err.transient) surface.degraded = true;
    }
  }

  return surface;
}

export function checkCapabilities(surface: ToolSurface): CheckResult {
  const base = {
    id: 'capabilities.tool-surface',
    policyRef: '§2.1–§2.4',
    title: 'Tool surface is inspectable and proportionate',
  };

  if (surface.source === 'none') {
    if (surface.degraded) {
      return {
        ...base,
        status: 'unverifiable',
        summary:
          'Tool surface could not be inspected because the package registry was unavailable. This reflects a scanner outage, not the server.',
        evidence: [],
        degraded: true,
      };
    }
    return {
      ...base,
      status: 'unverifiable',
      summary:
        'Tool surface could not be inspected (no reachable tools/list, no public package source). Per policy, unverifiability caps the overall grade.',
      evidence: [],
    };
  }

  const evidence: Evidence[] = [];
  const categories = new Set<RiskCategory>();

  if (surface.source === 'remote-tools-list') {
    evidence.push({ label: 'Tools exposed', value: String(surface.tools.length) });
    for (const tool of surface.tools) {
      const text = `${tool.name} ${tool.description ?? ''}`;
      for (const risk of TOOL_TEXT_RISKS) {
        // Underscore is a word character, so \bshell\b never matches inside
        // run_shell. Separators are normalised to spaces before name matching.
        const subject = risk.scope === 'name' ? tool.name.replace(/[_-]+/g, ' ') : text;
        if (risk.regex.test(subject)) {
          categories.add(risk.category);
          evidence.push({ label: `${tool.name}`, value: `${risk.category}` });
        }
      }
    }
  } else {
    for (const hit of surface.sourceRiskHits) {
      categories.add(hit.category);
      evidence.push({ label: `${hit.category} (${hit.label ?? hit.pattern})`, value: hit.file });
    }
  }

  // What was detected is recorded, not scored. §2.4: capability risk is
  // independent of how well-built a server is, and a server whose purpose IS
  // filesystem or shell access should not be graded down for doing its job.
  // The separate Capability Risk axis carries this; computeCapabilityRisk()
  // reads it back from exactly this evidence entry.
  const detected = [...categories];
  evidence.push({
    label: CAPABILITY_EVIDENCE_LABEL,
    value: detected.length > 0 ? detected.join(', ') : 'none',
  });

  const inspectedNote =
    surface.source === 'remote-tools-list'
      ? `${surface.tools.length} tool(s) enumerated`
      : 'Package source scanned';
  const summary =
    detected.length > 0
      ? `${inspectedNote}. Capabilities detected: ${detected.join(', ')}. Reported as capability risk (§2.4); whether each is essential to the server's stated purpose is §2.3 and remains a manual judgement.`
      : `${inspectedNote}; no high-risk capability signals.`;

  return { ...base, status: 'pass', summary, evidence };
}

/* ---------------- remote: minimal MCP streamable-HTTP client ---------------- */

function isRecord(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function isString(v: unknown): v is string {
  return typeof v === 'string';
}

function isStringArray(v: unknown): v is string[] {
  return Array.isArray(v) && v.every(isString);
}

function isValidToolInfo(v: unknown): v is { name: string; description?: string; inputSchema?: unknown } {
  if (!isRecord(v)) return false;
  if (!isString(v.name)) return false;
  if (v.description !== undefined && !isString(v.description)) return false;
  return true;
}

function isToolsListResult(v: unknown): v is { tools?: Array<{ name: string; description?: string; inputSchema?: unknown }> } {
  if (!isRecord(v)) return false;
  const tools = v.tools;
  if (tools === undefined) return true;
  if (!Array.isArray(tools)) return false;
  return tools.every(isValidToolInfo);
}

interface NamedEntry {
  name: string;
  description?: string;
}

function isValidNamedEntry(v: unknown): v is NamedEntry {
  if (!isRecord(v)) return false;
  return isString(v.name);
}

function isNamedEntriesResult(v: unknown, key: string): v is Record<string, NamedEntry[]> {
  if (!isRecord(v)) return false;
  const list = v[key];
  if (!Array.isArray(list)) return false;
  return list.every(isValidNamedEntry);
}

async function tryRemoteToolsList(
  ctx: CheckContext,
  url: string,
): Promise<{
  tools?: ToolInfo[];
  authRequired?: boolean;
  instructions?: string;
  prompts?: NamedText[];
  resources?: NamedText[];
}> {
  try {
    const initRes = await rpc(ctx, url, undefined, {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'mcpscorecard', version: '0.1.0' },
      },
    });
    if (initRes.status === 401 || initRes.status === 403) return { authRequired: true };
    if (!initRes.ok) return {};

    const initResult = isRecord(initRes.body?.result) ? initRes.body!.result : undefined;
    const instructions = isString(initResult?.instructions) ? initResult!.instructions : undefined;
    const caps = isRecord(initResult?.capabilities) ? initResult!.capabilities : undefined;

    const sessionId = initRes.response.headers.get('mcp-session-id') ?? undefined;
    await rpc(ctx, url, sessionId, { jsonrpc: '2.0', method: 'notifications/initialized' }).catch(() => undefined);

    // Prompts and resources also expose server-authored, model-facing text. Only
    // ask when the server advertised the capability, so we add no calls otherwise.
    let prompts: NamedText[] | undefined;
    if (caps?.prompts) {
      const r = await rpc(ctx, url, sessionId, { jsonrpc: '2.0', id: 3, method: 'prompts/list' }).catch(() => undefined);
      const promptsResult = r?.body?.result;
      if (promptsResult && isNamedEntriesResult(promptsResult, 'prompts')) {
        prompts = promptsResult.prompts!.map((p: NamedEntry) => ({ name: p.name, description: p.description }));
      }
    }
    let resources: NamedText[] | undefined;
    if (caps?.resources) {
      const r = await rpc(ctx, url, sessionId, { jsonrpc: '2.0', id: 4, method: 'resources/list' }).catch(() => undefined);
      const resourcesResult = r?.body?.result;
      if (resourcesResult && isNamedEntriesResult(resourcesResult, 'resources')) {
        resources = resourcesResult.resources!.map((x: NamedEntry) => ({ name: x.name, description: x.description }));
      }
    }

    const listRes = await rpc(ctx, url, sessionId, { jsonrpc: '2.0', id: 2, method: 'tools/list' });
    if (!listRes.ok) return { instructions, prompts, resources };
    const result = listRes.body?.result;
    if (!result || !isToolsListResult(result) || !result.tools) return { instructions, prompts, resources };
    return {
      tools: result.tools.map((t) => ({ name: t.name, description: t.description, inputSchema: t.inputSchema })),
      instructions,
      prompts,
      resources,
    };
  } catch {
    return {};
  }
}

async function rpc(
  ctx: CheckContext,
  url: string,
  sessionId: string | undefined,
  payload: unknown,
): Promise<{ ok: boolean; status: number; response: Response; body?: { result?: unknown } }> {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
  };
  if (sessionId) headers['mcp-session-id'] = sessionId;
  const response = await fetchWithTimeout(ctx, url, { method: 'POST', headers, body: JSON.stringify(payload) });
  if (!response.ok) return { ok: false, status: response.status, response };

  const contentType = response.headers.get('content-type') ?? '';
  let body: { result?: unknown } | undefined;
  if (contentType.includes('text/event-stream')) {
    body = parseFirstSseJson(await response.text());
  } else if (contentType.includes('json')) {
    body = (await response.json()) as { result?: unknown };
  }
  return { ok: true, status: response.status, response, body };
}

function parseFirstSseJson(text: string): { result?: unknown } | undefined {
  let dataBuffer = '';
  for (const line of text.split('\n')) {
    if (line.startsWith('data:')) {
      dataBuffer += (dataBuffer ? '' : '') + line.slice(5).replace(/^ /, '');
      continue;
    }
    if (line.trim() === '' && dataBuffer) {
      try {
        return JSON.parse(dataBuffer) as { result?: unknown };
      } catch {
        dataBuffer = '';
        continue;
      }
    }
  }
  if (dataBuffer) {
    try {
      return JSON.parse(dataBuffer) as { result?: unknown };
    } catch {
      return undefined;
    }
  }
  return undefined;
}

/* ---------------- package archive: static scan (never executed) ---------------- */

interface TarballScan {
  hits: Array<RiskHit & { label?: string }>;
  descriptionTools: ToolInfo[];
}

function stripArchiveRoot(name: string): string {
  const i = name.indexOf('/');
  return i === -1 ? name : name.slice(i + 1);
}

/** Vendored or generated code: never the server's own authored behaviour. */
const VENDORED_RE = /(^|\/)(node_modules|__pycache__|vendor)\//;
const METADATA_RE = /\.(dist-info|egg-info)\//;

/**
 * Packaging, test and example code. These reach the archive but are not the MCP
 * server's runtime, so capabilities found here are not capabilities the server
 * exposes to a model. In the 2026-07 corpus scripts/install.js alone produced
 * more §2 hits than every other file combined, purely because npm install scripts
 * necessarily use child_process and fs.
 *
 * NOTE: an install script spawning processes IS a real supply-chain risk, it is
 * just a §1 provenance/package-hygiene finding rather than a §2 capability-scope
 * one. Reporting it as "this server exposes process execution to the model" is a
 * different and false claim. TODO(v1.1): surface it in package-hygiene instead.
 */
const NON_RUNTIME_RE =
  /(^|\/)(scripts?|tests?|__tests__|__mocks__|spec|examples?|docs?|benchmarks?|fixtures)\//i;
const TEST_FILE_RE = /\.(test|spec)\.[cm]?[jt]s$|_test\.py$|^test_.*\.py$/i;

/** Bundled output: contains transitive dependency code inlined, so it over-reports. */
const BUNDLED_RE = /(^|\/)(dist|build|out|bundle)\//i;
const MINIFIED_RE = /\.min\.[cm]?js$/i;

/** True when the archive ships readable authored source, making bundled output redundant. */
function hasAuthoredSourceTree(names: string[]): boolean {
  return names.some((n) => {
    const rel = stripArchiveRoot(n);
    if (!SOURCE_FILE_RE.test(rel)) return false;
    if (VENDORED_RE.test(rel) || NON_RUNTIME_RE.test(rel) || BUNDLED_RE.test(rel)) return false;
    return true;
  });
}

/**
 * Exported for testing. `preferSource` is set when the package ships an authored
 * source tree, in which case bundled output is skipped as a duplicate view of the
 * same code carrying its dependencies' capabilities as well as its own.
 */
export function shouldScanSourceFile(name: string, preferSource = false): boolean {
  const rel = stripArchiveRoot(name);
  if (!SOURCE_FILE_RE.test(rel)) return false;
  if (VENDORED_RE.test(rel) || METADATA_RE.test(rel)) return false;
  if (NON_RUNTIME_RE.test(rel) || TEST_FILE_RE.test(rel)) return false;
  if (MINIFIED_RE.test(rel)) return false;
  if (preferSource && BUNDLED_RE.test(rel)) return false;
  return true;
}

function scanArchiveBytes(tarBytes: Uint8Array): TarballScan {
  const scan: TarballScan = { hits: [], descriptionTools: [] };
  let filesScanned = 0;
  // One cheap pass over headers first: whether authored source exists decides
  // whether bundled output counts, and that has to be known before scanning.
  const preferSource = hasAuthoredSourceTree([...iterateTar(tarBytes)].map((e) => e.name));
  for (const entry of iterateTar(tarBytes)) {
    if (filesScanned >= MAX_SCANNED_FILES) break;
    if (!shouldScanSourceFile(entry.name, preferSource)) continue;
    filesScanned++;
    const rel = stripArchiveRoot(entry.name);
    const text = new TextDecoder('utf-8', { fatal: false, ignoreBOM: false }).decode(entry.data);

    for (const pattern of RISK_PATTERNS) {
      const match = pattern.regex.exec(text);
      if (match) {
        scan.hits.push({
          category: pattern.category,
          label: pattern.label,
          pattern: match[0],
          file: rel,
        });
      }
    }
    // Description string literals near MCP tool contexts feed the §5 poisoning scan.
    if (/@modelcontextprotocol|registerTool|FastMCP|mcp/i.test(text)) {
      for (const m of text.matchAll(/description:\s*(["'`])((?:(?!\1)[\s\S]){10,500})\1/g)) {
        if (scan.descriptionTools.length >= 100) break;
        scan.descriptionTools.push({
          name: `${rel} (source literal)`,
          description: m[2],
        });
      }
      // Python FastMCP / decorator style: description="..."
      for (const m of text.matchAll(/description\s*=\s*(["'])((?:(?!\1)[\s\S]){10,500})\1/g)) {
        if (scan.descriptionTools.length >= 100) break;
        scan.descriptionTools.push({
          name: `${rel} (source literal)`,
          description: m[2],
        });
      }
    }
  }
  // Deduplicate hits by category+label+pattern to avoid ballooning evidence.
  const seen = new Map<string, (typeof scan.hits)[number]>();
  for (const hit of scan.hits) {
    const key = `${hit.category}:${hit.label}:${hit.pattern}`;
    if (!seen.has(key)) seen.set(key, hit);
  }
  scan.hits = [...seen.values()];
  return scan;
}

async function tryNpmTarballScan(ctx: CheckContext, pkg: string): Promise<TarballScan | undefined> {
  try {
    const metaRes = await fetchWithTimeout(ctx, `https://registry.npmjs.org/${encodeURIComponent(pkg)}`);
    // A 404 means the package is not published; anything else means npm failed us.
    if (!metaRes.ok) throw new UpstreamUnavailable(metaRes.status === 404 ? undefined : `npm HTTP ${metaRes.status}`);
    const meta = (await metaRes.json()) as {
      'dist-tags'?: Record<string, string>;
      versions?: Record<string, { dist?: { tarball?: string; unpackedSize?: number } }>;
    };
    const latest = meta['dist-tags']?.latest;
    const dist = latest ? meta.versions?.[latest]?.dist : undefined;
    if (!dist?.tarball) return undefined;
    if (dist.unpackedSize && dist.unpackedSize > TARBALL_MAX_BYTES * 4) return undefined;

    const tarRes = await fetchWithTimeout(ctx, dist.tarball);
    if (!tarRes.ok || !tarRes.body) return undefined;

    const gunzipped = tarRes.body.pipeThrough(new DecompressionStream('gzip'));
    const tarBytes = await readCapped(gunzipped, TARBALL_MAX_BYTES);
    if (!tarBytes) return undefined;
    return scanArchiveBytes(tarBytes);
  } catch (err) {
    if (err instanceof UpstreamUnavailable && err.transient) throw err;
    return undefined;
  }
}

async function tryPypiSdistScan(ctx: CheckContext, pkg: string): Promise<TarballScan | undefined> {
  try {
    const metaRes = await fetchWithTimeout(ctx, `https://pypi.org/pypi/${encodeURIComponent(pkg)}/json`);
    if (!metaRes.ok) throw new UpstreamUnavailable(metaRes.status === 404 ? undefined : `PyPI HTTP ${metaRes.status}`);
    const meta = (await metaRes.json()) as {
      urls?: Array<{
        packagetype?: string;
        url?: string;
        size?: number;
        filename?: string;
        yanked?: boolean;
      }>;
    };
    const sdist = (meta.urls ?? []).find(
      (u) =>
        u.packagetype === 'sdist' &&
        !u.yanked &&
        typeof u.url === 'string' &&
        /\.tar\.gz$/i.test(u.filename ?? u.url),
    );
    if (!sdist?.url) return undefined;
    if (sdist.size && sdist.size > TARBALL_MAX_BYTES * 4) return undefined;

    const tarRes = await fetchWithTimeout(ctx, sdist.url);
    if (!tarRes.ok || !tarRes.body) return undefined;

    const gunzipped = tarRes.body.pipeThrough(new DecompressionStream('gzip'));
    const tarBytes = await readCapped(gunzipped, TARBALL_MAX_BYTES);
    if (!tarBytes) return undefined;
    return scanArchiveBytes(tarBytes);
  } catch (err) {
    if (err instanceof UpstreamUnavailable && err.transient) throw err;
    return undefined;
  }
}

/** Exported for testing. */
export async function readCapped(stream: ReadableStream<Uint8Array>, cap: number): Promise<Uint8Array | undefined> {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = stream.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > cap) {
        await reader.cancel();
        break; // scan what we have - partial coverage beats none
      }
      chunks.push(value);
    }
  } catch {
    return undefined;
  }
  const out = new Uint8Array(Math.min(total, cap));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk.subarray(0, out.length - offset), offset);
    offset += chunk.byteLength;
    if (offset >= out.length) break;
  }
  return out;
}

/** Exported for testing. Minimal ustar reader - enough for npm tarballs ("package/..." paths). */
export function* iterateTar(bytes: Uint8Array): Generator<{ name: string; data: Uint8Array }> {
  let offset = 0;
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every((b) => b === 0)) break;
    const name = readString(header, 0, 100);
    const size = parseInt(readString(header, 124, 12).trim() || '0', 8);
    const type = String.fromCharCode(header[156] ?? 48);
    offset += 512;
    if (Number.isNaN(size) || size < 0) break;
    const data = bytes.subarray(offset, Math.min(offset + size, bytes.length));
    if (type === '0' || type === '\0') {
      yield { name, data };
    }
    offset += Math.ceil(size / 512) * 512;
  }
}

/** Exported for testing. */
export function readString(bytes: Uint8Array, start: number, length: number): string {
  const slice = bytes.subarray(start, start + length);
  const end = slice.indexOf(0);
  return new TextDecoder().decode(end === -1 ? slice : slice.subarray(0, end));
}

/* ---------------- schema hash (rug-pull detection, §5.3) ---------------- */

export async function computeToolSchemaHash(tools: ToolInfo[]): Promise<string> {
  const canonical = JSON.stringify(
    [...tools]
      .sort((a, b) => a.name.localeCompare(b.name))
      .map((t) => ({ name: t.name, description: t.description ?? '', inputSchema: t.inputSchema ?? null })),
    stableReplacer,
  );
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function stableReplacer(_key: string, value: unknown): unknown {
  if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
    return Object.keys(value as Record<string, unknown>)
      .sort()
      .reduce<Record<string, unknown>>((acc, k) => {
        acc[k] = (value as Record<string, unknown>)[k];
        return acc;
      }, {});
  }
  return value;
}

