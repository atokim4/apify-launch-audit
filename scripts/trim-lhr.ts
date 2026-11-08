/**
 * Shrinks a full Lighthouse JSON report to the fields `summarizeLhr` reads, replacing the site's
 * URL, so real reports can be kept as small, anonymous test fixtures.
 *
 *   npx tsx scripts/trim-lhr.ts report.json test/fixtures/lhr/name.json
 */
import { readFile, writeFile } from 'node:fs/promises';
import type { LhrAudit, LhrLike } from '../src/lighthouse/summary.js';

const [input, output] = process.argv.slice(2);
if (!input || !output) {
  console.error('usage: trim-lhr <report.json> <fixture.json>');
  process.exit(1);
}

const lhr = JSON.parse(await readFile(input, 'utf8')) as LhrLike;

function trimAudit(a: LhrAudit): LhrAudit {
  const d = a.details;
  const details = d
    ? {
        ...(d.type ? { type: d.type } : {}),
        ...(d.overallSavingsMs !== undefined ? { overallSavingsMs: d.overallSavingsMs } : {}),
        ...(d.overallSavingsBytes !== undefined ? { overallSavingsBytes: d.overallSavingsBytes } : {}),
        // Only the resource summary's rows are read; other items carry the site's URLs.
        ...(a.id === 'resource-summary' && d.items ? { items: d.items } : {}),
      }
    : undefined;
  return {
    id: a.id,
    title: a.title,
    score: a.score,
    ...(a.scoreDisplayMode ? { scoreDisplayMode: a.scoreDisplayMode } : {}),
    ...(a.numericValue !== undefined ? { numericValue: a.numericValue } : {}),
    ...(a.numericUnit ? { numericUnit: a.numericUnit } : {}),
    ...(a.metricSavings ? { metricSavings: a.metricSavings } : {}),
    ...(details ? { details } : {}),
  };
}

const performanceIds = new Set((lhr.categories.performance?.auditRefs ?? []).map((r) => r.id));
const trimmed: LhrLike = {
  lighthouseVersion: lhr.lighthouseVersion,
  finalDisplayedUrl: 'https://shop.example/',
  configSettings: { formFactor: lhr.configSettings?.formFactor ?? 'mobile' },
  categories: Object.fromEntries(
    Object.entries(lhr.categories).map(([key, c]) => [
      key,
      c && { score: c.score, ...(key === 'performance' && c.auditRefs ? { auditRefs: c.auditRefs.map((r) => ({ id: r.id, ...(r.group ? { group: r.group } : {}) })) } : {}) },
    ]),
  ),
  audits: Object.fromEntries(
    Object.values(lhr.audits)
      .filter((a): a is LhrAudit => a !== undefined && (performanceIds.has(a.id) || a.id === 'resource-summary'))
      .map((a) => [a.id, trimAudit(a)]),
  ),
  runWarnings: [],
};
await writeFile(output, `${JSON.stringify(trimmed, null, 1)}\n`);
