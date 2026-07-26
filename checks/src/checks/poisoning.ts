/**
 * §5 Server-supplied instruction integrity - pattern-based tool-poisoning scan.
 *
 * An MCP server supplies several channels of text that clients load into the
 * model's context and that the model tends to follow: the initialize
 * `instructions` field (the spec permits injecting it into the system prompt),
 * every tool's name and description, the string fields inside tool input
 * schemas, and prompt/resource metadata. A poisoned entry in ANY of these
 * attacks the agent without the tool ever being called. So the real question is
 * not "does this contain bad words" but "is an external server quietly making
 * itself a co-author of the agent's policy" - excessive authority, not vocabulary.
 *
 * This scan is deliberately pattern-based and deterministic (no LLM): it
 * identifies COMMON INDICATORS of poisoning and authority-assertion, not every
 * possible injection. Semantic prompt injection (natural-language steering with
 * no tell-tale phrase) is the known ceiling of any pattern scanner and is out of
 * scope here by design; see §5 of the policy.
 *
 * Layered, cheapest first: length limit (anti-stuffing) -> pattern match over
 * each model-facing text item. Patterns are public; a description that merely
 * dodges these exact strings while embedding instructions will still read
 * suspiciously in the evidence we surface.
 */

import type { CheckResult, Evidence, ToolSurface } from '../types.js';

/** Descriptions above this are flagged as anti-stuffing signal, independent of content. */
export const MAX_DESCRIPTION_CHARS = 2048;
/** The initialize instructions field legitimately documents a whole server, so it gets more room. */
export const MAX_INSTRUCTIONS_CHARS = 4096;

type Severity = 'critical' | 'fail' | 'warn';

interface PoisonPattern {
  name: string;
  regex: RegExp;
  severity: Severity;
  /** 'description' patterns skip schema-derived text (avoids flagging $schema URIs etc.) */
  scope?: 'description' | 'all';
}

export const POISON_PATTERNS: PoisonPattern[] = [
  {
    name: 'invisible/zero-width characters',
    // zero-width spaces/joiners, bidi marks, soft hyphen, BOM, Unicode "tag" block
    regex: /[\u200B-\u200F\u2060-\u2064\u00AD\uFEFF\u{E0000}-\u{E007F}]/u,
    severity: 'fail',
  },
  {
    name: 'override-instructions phrase',
    regex: /\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|messages?)/i,
    severity: 'fail',
  },
  {
    name: 'concealment directive',
    regex: /\bdo\s+not\s+(tell|inform|reveal|mention|show|alert|notify)\b[^.]{0,60}\b(user|human)\b/i,
    severity: 'fail',
  },
  {
    name: 'credential-priority directive',
    // authority assertion: server tells the agent to read secrets/env first, before its actual work
    regex: /\b(read|fetch|load|retrieve|access|collect|obtain|gather)\b[^.]{0,40}\b(secret|credential|api[_ ]?key|access[_ ]?token|password|\.env|environment\s+variables?)s?\b[^.]{0,40}\b(first|before\s+(?:you|doing|anything|any|calling)|immediately|at\s+the\s+start|to\s+begin|up\s?front)\b/i,
    severity: 'critical',
  },
  {
    name: 'content suppression directive',
    // authority assertion: server dictates what the agent may not say about others
    regex: /\b(never|do\s+not|don'?t|avoid|refuse\s+to)\s+(mention|reveal|recommend|suggest|discuss|name|acknowledge|refer\s+to)\b[^.]{0,50}\b(competitor|competing|rival|alternative|other\s+(?:tools?|products?|vendors?|brands?|services?|servers?))\b/i,
    severity: 'warn',
  },
  {
    name: 'imperative to the model',
    regex: /\byou\s+(must|should)\s+(always|never|first|instead)\b/i,
    severity: 'warn',
  },
  {
    name: 'cross-tool shadowing',
    // Capture group 1 is the referenced identifier, group 2 the optional noun
    // phrase. Both are needed by the context filter: the attack is redirecting the
    // model to or away from ANOTHER server's tool, so a bare English word
    // ("instead of asking") and a reference to this server's own tool are both
    // benign. The noun is allowed to sit a couple of words out so that a
    // multi-word reference ("the built-in email tool") still registers as one.
    // See isContextualFalsePositive().
    regex: /\b(?:instead\s+of|rather\s+than|in\s+place\s+of|before\s+(?:using|calling))\s+(?:the\s+)?[`'"]?([\w.-]+)[`'"]?((?:\s+[\w.-]+){0,2}\s*(?:tool|server|function))?/i,
    severity: 'warn',
  },
  {
    name: 'pseudo-system markup',
    // fake chat/role/instruction delimiters models may treat as privileged.
    // <important> is deliberately absent: it is a mainstream, documented prompt
    // idiom rather than an impersonation of a privileged channel.
    regex: /<\/?\s*(system|assistant|user|hidden|secret|instructions?)\s*>/i,
    severity: 'fail',
  },
  {
    name: 'hidden markup comment',
    // instructions tucked into an HTML/markdown comment: invisible when rendered
    regex: /<!--[\s\S]*?(ignore|instead|do not|always|never|system|credential|secret)[\s\S]*?-->/i,
    severity: 'fail',
  },
  {
    name: 'non-http URI scheme',
    // javascript:/vbscript:/file: are payload-bearing on sight. data: is not:
    // schemas legitimately document accepted image formats ("data:image/png;base64,..."),
    // so it only counts with an actual embedded payload of meaningful length.
    regex: /\b(?:javascript|vbscript|file):[^\s)"']{4,}|\bdata:[\w/+.-]+;base64,[A-Za-z0-9+/=]{40,}/i,
    severity: 'fail',
  },
  {
    name: 'embedded URL',
    // Host allow-listing happens in the context filter, which knows the server's
    // own domains. A vendor linking its own docs is not an exfiltration signal;
    // an unrelated third-party host in a tool description is.
    regex: /https?:\/\/[^\s)"'`<>]{8,}/i,
    severity: 'warn',
    scope: 'description',
  },
];

/** Hosts that are never treated as third-party in a tool description. */
const NEUTRAL_URL_HOSTS = [/^(www\.)?github\.com$/i, /^docs\./i, /(^|\.)example\.com$/i, /(^|\.)example\.org$/i];

/**
 * What the scan knows about the server beyond its raw text. Without this the
 * pattern set cannot distinguish self-reference from cross-server redirection,
 * which was the dominant source of false positives in the 2026-07 corpus.
 */
export interface PoisonScanContext {
  /** Tool names exposed by this same server, lowercased. */
  toolNames: Set<string>;
  /** Domains this server legitimately owns (its own endpoint, its vendor domain). */
  ownHosts: string[];
}

/** Reverse-DNS registry names encode the vendor domain: ai.acme/server -> acme.ai */
function vendorHostFromRegistryName(registryName: string | undefined): string | undefined {
  if (!registryName) return undefined;
  const namespace = registryName.split('/')[0];
  const labels = namespace?.split('.').filter(Boolean) ?? [];
  if (labels.length < 2) return undefined;
  return [...labels].reverse().join('.').toLowerCase();
}

export function buildPoisonScanContext(surface: ToolSurface, target?: PoisonTargetInfo): PoisonScanContext {
  const ownHosts: string[] = [];
  if (target?.remoteUrl) {
    try {
      const host = new URL(target.remoteUrl).hostname.toLowerCase();
      ownHosts.push(host);
      // MCP endpoints almost always sit on an api./mcp. subdomain while the
      // vendor's docs live on the parent, so treat one level up as own too.
      const labels = host.split('.');
      if (labels.length > 2) ownHosts.push(labels.slice(1).join('.'));
    } catch {
      // Unparseable endpoint just means no host to allow-list.
    }
  }
  const vendorHost = vendorHostFromRegistryName(target?.registryName);
  if (vendorHost) ownHosts.push(vendorHost);
  return {
    toolNames: new Set(surface.tools.map((t) => t.name.toLowerCase())),
    ownHosts,
  };
}

/** The subset of ScanTarget the poisoning scan needs; keeps this check free of resolver types. */
export interface PoisonTargetInfo {
  remoteUrl?: string;
  registryName?: string;
}

function hostOf(url: string): string | undefined {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

function isOwnOrNeutralHost(host: string, ctx: PoisonScanContext): boolean {
  if (NEUTRAL_URL_HOSTS.some((re) => re.test(host))) return true;
  return ctx.ownHosts.some((own) => host === own || host.endsWith(`.${own}`));
}

/**
 * Determiners and pronouns naming no particular tool. "before calling this tool"
 * and "instead of any other tool" are generic usage notes, so they stay benign
 * even though the noun is present.
 */
const GENERIC_REFERENTS = new Set([
  'this', 'that', 'these', 'those', 'the', 'a', 'an', 'any', 'other', 'another',
  'each', 'some', 'it', 'its', 'them', 'their', 'such', 'either', 'both', 'no',
]);

/**
 * A tool identifier looks like code, not prose: snake_case, dotted, or camelCase.
 * "asking" and "averaging" are English; "get_user_email" is a tool.
 *
 * Kebab-case is deliberately excluded: MCP tool names conventionally use
 * snake_case, while hyphenated English ("dead-end", "read-only") is common in
 * descriptions. A hyphenated name that really is a tool on this server is still
 * caught by the toolNames lookup, so the only cost is under-flagging references
 * to foreign kebab-case tools, which is the safer direction to err.
 */
function looksLikeToolIdentifier(word: string): boolean {
  if (word.length < 3) return false;
  if (GENERIC_REFERENTS.has(word)) return false;
  return /[_.]/.test(word) || /[a-z][A-Z]/.test(word);
}

/**
 * Second-stage filter: given a pattern hit, decide whether the surrounding
 * context makes it benign. Returning true drops the hit entirely.
 */
export function isContextualFalsePositive(
  patternName: string,
  match: RegExpExecArray,
  ctx: PoisonScanContext,
): boolean {
  if (patternName === 'cross-tool shadowing') {
    // The identifier class includes '.' so it can match dotted tool names, which
    // means a sentence-ending period rides along ("...before calling foo_bar.").
    const identifier = (match[1] ?? '').toLowerCase().replace(/[.\-]+$/, '');
    const noun = match[2];
    // "instead of the X tool" states the redirection outright, unless X names no
    // particular tool ("before calling this tool").
    if (noun) return GENERIC_REFERENTS.has(identifier);
    // Pointing at one of its own tools is ordinary sequencing guidance.
    if (ctx.toolNames.has(identifier)) return true;
    // Anything that is not shaped like a tool name is just English prose.
    return !looksLikeToolIdentifier(identifier);
  }

  if (patternName === 'embedded URL') {
    const host = hostOf(match[0]);
    if (!host) return true;
    return isOwnOrNeutralHost(host, ctx);
  }

  if (patternName === 'pseudo-system markup') {
    // "https://host/pay/<id>?s=<secret>" is a URL template, not a fake channel.
    const before = match.input.slice(Math.max(0, match.index - 80), match.index);
    return /https?:\/\/\S*$/.test(before);
  }

  return false;
}

/**
 * Recursively collect human-readable string fields from a JSON Schema. These
 * (description/title/examples/default/enum) are surfaced to the model just like
 * the top-level description, so a payload buried in a nested property counts.
 */
export function extractSchemaText(schema: unknown, depth = 0): string[] {
  if (depth > 8 || schema == null) return [];
  const out: string[] = [];
  if (Array.isArray(schema)) {
    for (const item of schema) out.push(...extractSchemaText(item, depth + 1));
    return out;
  }
  if (typeof schema === 'object') {
    for (const [key, value] of Object.entries(schema as Record<string, unknown>)) {
      if (['description', 'title', 'default'].includes(key) && typeof value === 'string') {
        out.push(value);
      } else if (['examples', 'enum'].includes(key) && Array.isArray(value)) {
        for (const v of value) if (typeof v === 'string') out.push(v);
      } else if (typeof value === 'object') {
        out.push(...extractSchemaText(value, depth + 1));
      }
    }
  }
  return out;
}

/** One model-facing text item to scan. 'schema' items skip description-only patterns. */
interface ScanItem {
  label: string;
  text: string;
  kind: 'description' | 'schema';
}

export function checkPoisoning(surface: ToolSurface, target?: PoisonTargetInfo): CheckResult {
  const scanContext = buildPoisonScanContext(surface, target);
  const base = {
    id: 'poisoning.patterns',
    policyRef: '§5.1–§5.4',
    title: 'Server-supplied instructions free of poisoning indicators',
  };

  // Build the full set of model-facing text items across every server-supplied channel.
  const items: ScanItem[] = [];
  const evidence: Evidence[] = [];
  let worst: 'pass' | 'warn' | 'fail' = 'pass';
  const bump = (severity: Severity) => {
    if (severity === 'critical' || severity === 'fail') worst = 'fail';
    else if (worst === 'pass') worst = 'warn';
  };

  // Anti-stuffing length check, applied where a length ceiling makes sense.
  const lengthCheck = (label: string, text: string, limit: number) => {
    if (text.length > limit) {
      evidence.push({ label: `${label}: oversized`, value: `${text.length} chars (limit ${limit})` });
      bump('warn');
    }
  };

  // 1. initialize instructions (the highest-authority channel: the system prompt).
  if (surface.serverInstructions) {
    items.push({ label: 'server instructions', text: surface.serverInstructions, kind: 'description' });
    lengthCheck('server instructions', surface.serverInstructions, MAX_INSTRUCTIONS_CHARS);
  }

  // 2. tools: name + description scanned as prose, schema string fields scanned separately.
  for (const tool of surface.tools) {
    const description = tool.description ?? '';
    items.push({ label: tool.name, text: [tool.name, description].join('\n'), kind: 'description' });
    lengthCheck(`${tool.name} description`, description, MAX_DESCRIPTION_CHARS);
    const schemaText = extractSchemaText(tool.inputSchema).join('\n');
    if (schemaText) items.push({ label: `${tool.name} (schema)`, text: schemaText, kind: 'schema' });
  }

  // 3. prompts and 4. resources: names/descriptions are model-facing too (URIs left alone).
  for (const p of surface.prompts ?? []) {
    items.push({ label: `prompt: ${p.name}`, text: [p.name, p.description ?? ''].join('\n'), kind: 'description' });
  }
  for (const r of surface.resources ?? []) {
    items.push({ label: `resource: ${r.name}`, text: [r.name, r.description ?? ''].join('\n'), kind: 'description' });
  }

  if (items.length === 0) {
    return {
      ...base,
      status: 'unverifiable',
      summary: 'No server-supplied instructions or tool descriptions were obtainable to scan.',
      evidence: [],
    };
  }

  let criticalHits = 0;
  for (const item of items) {
    for (const pattern of POISON_PATTERNS) {
      if (item.kind === 'schema' && pattern.scope === 'description') continue;
      const match = pattern.regex.exec(item.text);
      if (!match) continue;
      if (isContextualFalsePositive(pattern.name, match, scanContext)) continue;
      const critical = pattern.severity === 'critical';
      if (critical) criticalHits++;
      evidence.push({
        label: `${item.label}: ${critical ? 'CRITICAL - ' : ''}${pattern.name}`,
        value: truncate(match[0], 120),
      });
      bump(pattern.severity);
    }
  }

  const scannedCount = items.length;
  let summary: string;
  if (worst === 'pass') {
    summary = `No poisoning indicators found across ${scannedCount} server-supplied text item(s).`;
  } else {
    const critNote = criticalHits > 0 ? ` including ${criticalHits} critical` : '';
    summary = `${evidence.length} suspicious indicator(s)${critNote} found in server-supplied instructions, tool descriptions, or schemas.`;
  }

  return { ...base, status: worst, summary, evidence };
}

function truncate(s: string, n: number): string {
  return s.length > n ? `${s.slice(0, n)}…` : s;
}
