import { Actor, log } from 'apify';
import { auditSite } from './audit.js';
import { toDatasetItem } from './dataset.js';
import { parseInput } from './input.js';
import { toMarkdownReport } from './report.js';
import type { AuditResult } from './types.js';

/** Pay-per-event: one charge per site that was reachable and fully audited. */
export const CHARGE_EVENT = 'site-audited';

await Actor.main(async () => {
  const input = parseInput(await Actor.getInput());
  log.info(`Auditing ${input.urls.length} site(s)`);

  const charging = Actor.getChargingManager();
  const results: AuditResult[] = [];
  for (const url of input.urls) {
    if (charging.calculateMaxEventChargeCountWithinLimit(CHARGE_EVENT) < 1) {
      log.info('Spending limit reached, remaining URLs were skipped.');
      break;
    }
    const result = await auditSite(url, { maxBundles: input.maxBundles, timeoutMs: input.timeoutSecs * 1000 });
    results.push(result);
    await Actor.pushData(toDatasetItem(result));

    if (result.error) {
      log.warning(`${url}: ${result.error} (not charged)`);
      continue;
    }
    log.info(`${result.url}: ${result.score}/100, ${result.findings.length} finding(s)`);
    const charge = await Actor.charge({ eventName: CHARGE_EVENT });
    if (charge.eventChargeLimitReached) {
      log.info('Spending limit reached, remaining URLs were skipped.');
      break;
    }
  }

  await Actor.setValue('OUTPUT', toMarkdownReport(results), { contentType: 'text/markdown; charset=utf-8' });
  log.info('Report saved to the key-value store as OUTPUT');
});
