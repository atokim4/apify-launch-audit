import { auditSite, normalizeUrl } from '../audit.js';
import { assertPublicHost } from '../network.js';
import { combinedScore } from '../score.js';
import type { AuditOptions, AuditResult, LighthouseFailure, LighthouseSummary } from '../types.js';
import { isLighthouseFailure, type LighthouseOptions, runLighthouse } from './run.js';

export { isLighthouseFailure, LIGHTHOUSE_DEFAULTS, type LighthouseOptions } from './run.js';

/** Attaches a Lighthouse result and, when both parts succeeded, the combined score. */
export function withLighthouse(result: AuditResult, lighthouse: LighthouseSummary | LighthouseFailure): AuditResult {
  const updated: AuditResult = { ...result, lighthouse };
  delete updated.combinedScore;
  if (!result.error && !isLighthouseFailure(lighthouse)) updated.combinedScore = combinedScore(result.score, lighthouse.scores);
  return updated;
}

async function guardedLighthouse(url: string, options: LighthouseOptions): Promise<LighthouseSummary | LighthouseFailure> {
  try {
    await assertPublicHost(url);
  } catch (err) {
    return { error: `Lighthouse skipped: ${(err as Error).message}`, durationMs: 0 };
  }
  return runLighthouse(url, options);
}

/**
 * Passive audit plus Lighthouse. Never throws.
 *
 * Locally (`allowPrivateNetwork`) both run at the same time to keep the total under a minute.
 * In hosted mode Chrome opens its own connections, outside the private-network guard of the
 * HTTP client, so Lighthouse only runs after the passive audit reached the site, against the
 * final URL that the guarded client already followed, and after a DNS check of that host.
 */
export async function auditSiteWithLighthouse(
  input: string,
  options: AuditOptions = {},
  lighthouse: LighthouseOptions = {},
): Promise<AuditResult> {
  if (options.allowPrivateNetwork) {
    let url: string | undefined;
    try {
      url = normalizeUrl(input);
    } catch {
      // auditSite reports the invalid URL
    }
    const [result, lh] = await Promise.all([
      auditSite(input, options),
      url ? runLighthouse(url, lighthouse) : Promise.resolve<LighthouseFailure>({ error: 'Lighthouse skipped: invalid URL', durationMs: 0 }),
    ]);
    return withLighthouse(result, lh);
  }

  const result = await auditSite(input, options);
  if (result.error || !result.finalUrl) {
    return withLighthouse(result, { error: 'Lighthouse skipped: the site could not be reached', durationMs: 0 });
  }
  return withLighthouse(result, await guardedLighthouse(result.finalUrl, lighthouse));
}
