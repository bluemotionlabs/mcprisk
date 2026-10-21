import type { CheckContext } from './types.js';

/**
 * `timeoutMs` overrides the per-scan default for a single call. Most upstreams
 * answer well inside it; the MCP registry's `?search=` is the exception, being
 * fast when its cache is warm and tens of seconds when it is not.
 */
export async function fetchWithTimeout(
  ctx: CheckContext,
  url: string,
  init?: RequestInit,
  timeoutMs?: number,
): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs ?? ctx.timeoutMs ?? 10_000);
  try {
    return await ctx.fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

export function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
