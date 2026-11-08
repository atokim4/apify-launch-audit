import { Actor, log } from 'apify';
import { auditSite } from './audit.js';
import { toDatasetItem } from './dataset.js';
import { parseInput } from './input.js';
import { toMarkdownReport } from './report.js';
import type { AuditResult } from './types.js';

/** Pay-per-event: one charge per site that was reachable and fully audited. */
export const CHARGE_EVENT = 'site-audited';
const LIGHTHOUSE_MIN_MEMORY_MB = 1024;

await Actor.main(async () => {
  const input = parseInput(await Actor.getInput());
  log.info(`Auditing ${input.urls.length} site(s)${input.lighthouse ? ' with Lighthouse' : ''}`);

  // Loaded only when asked for, so the plain audit never starts Chrome.
  const withLighthouse = input.lighthouse ? (await import('./lighthouse/index.js')).auditSiteWithLighthouse : undefined;
  const chromePath = process.env.CHROME_PATH ?? process.env.APIFY_CHROME_EXECUTABLE_PATH;
  const memoryMb = Number(process.env.ACTOR_MEMORY_MBYTES ?? process.env.APIFY_MEMORY_MBYTES ?? 0);
  if (input.lighthouse && memoryMb > 0 && memoryMb < LIGHTHOUSE_MIN_MEMORY_MB) {
    log.warning(`Lighthouse runs Chrome and needs at least ${LIGHTHOUSE_MIN_MEMORY_MB} MB; this run has ${memoryMb} MB, so Chrome may crash.`);
  }

  const charging = Actor.getChargingManager();
  const results: AuditResult[] = [];
  for (const url of input.urls) {
    if (charging.calculateMaxEventChargeCountWithinLimit(CHARGE_EVENT) < 1) {
      log.info('Spending limit reached, remaining URLs were skipped.');
      break;
    }
    const options = { maxBundles: input.maxBundles, timeoutMs: input.timeoutSecs * 1000 };
    const result = withLighthouse ? await withLighthouse(url, options, { ...(chromePath ? { chromePath } : {}) }) : await auditSite(url, options);
    results.push(result);
    await Actor.pushData(toDatasetItem(result));

    if (result.error) {
      log.warning(`${url}: ${result.error} (not charged)`);
      continue;
    }
    const combined = result.combinedScore !== undefined ? `, combined ${result.combinedScore}/100` : '';
    log.info(`${result.url}: ${result.score}/100${combined}, ${result.findings.length} finding(s)`);
    if (result.lighthouse && 'error' in result.lighthouse) log.warning(`${result.url}: ${result.lighthouse.error}`);
    const charge = await Actor.charge({ eventName: CHARGE_EVENT });
    if (charge.eventChargeLimitReached) {
      log.info('Spending limit reached, remaining URLs were skipped.');
      break;
    }
  }

  await Actor.setValue('OUTPUT', toMarkdownReport(results), { contentType: 'text/markdown; charset=utf-8' });
  log.info('Report saved to the key-value store as OUTPUT');
});
