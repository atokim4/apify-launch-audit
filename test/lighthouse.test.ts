import { describe, expect, it } from 'vitest';
import { toDatasetItem } from '../src/dataset.js';
import { withLighthouse } from '../src/lighthouse/index.js';
import { runLighthouse } from '../src/lighthouse/run.js';
import { summarizeLhr, topOpportunities } from '../src/lighthouse/summary.js';
import { combinedScore } from '../src/score.js';
import type { AuditResult } from '../src/types.js';
import { loadLhr } from './fixtures/lhr.js';

describe('summarizeLhr', () => {
  it('reads scores, metrics and transfer sizes from a real report', () => {
    const s = summarizeLhr(loadLhr('slow-images'), 12_345);
    expect(s).toMatchObject({
      lighthouseVersion: '13.6.0',
      formFactor: 'mobile',
      scores: { performance: 34, accessibility: 97, bestPractices: 81, seo: 92 },
      lcpMs: 16185,
      cls: 0,
      tbtMs: 3122,
      totalKb: 22066,
      jsKb: 931,
      jsRequests: 33,
      durationMs: 12_345,
    });
  });

  it('ranks opportunities by time saved, then bytes, and keeps three', () => {
    const ops = summarizeLhr(loadLhr('slow-images')).opportunities;
    expect(ops.map((o) => o.id)).toEqual(['image-delivery-insight', 'render-blocking-insight', 'unused-javascript']);
    expect(ops[0]).toMatchObject({ savingsMs: 4500, savingsBytes: 16_173_350 });
  });

  it('drops passing audits, metric audits and savings that are noise', () => {
    const ids = topOpportunities(loadLhr('fast'), 10).map((o) => o.id);
    expect(ids).not.toContain('largest-contentful-paint');
    expect(ids).not.toContain('network-dependency-tree-insight');
    for (const o of topOpportunities(loadLhr('frozen'), 10)) {
      expect(o.savingsMs >= 100 || o.savingsBytes >= 20 * 1024).toBe(true);
    }
  });

  it('keeps null scores as null instead of 0', () => {
    const lhr = loadLhr('fast');
    lhr.categories.performance = { score: null, auditRefs: [] };
    expect(summarizeLhr(lhr).scores.performance).toBeNull();
  });

  it('throws on a report that carries a runtime error', () => {
    const lhr = { ...loadLhr('fast'), runtimeError: { code: 'NO_FCP', message: 'The page did not paint any content.' } };
    expect(() => summarizeLhr(lhr)).toThrow(/NO_FCP/);
  });
});

describe('combinedScore', () => {
  it('weights security 50 %, performance 30 % and the rest 20 %', () => {
    expect(combinedScore(100, { performance: 100, accessibility: 100, bestPractices: 100, seo: 100 })).toBe(100);
    expect(combinedScore(80, { performance: 40, accessibility: 100, bestPractices: 100, seo: 100 })).toBe(72);
  });

  it('rescales when Lighthouse could not score a category', () => {
    expect(combinedScore(80, { performance: null, accessibility: null, bestPractices: null, seo: null })).toBe(80);
  });
});

describe('withLighthouse', () => {
  const base: AuditResult = {
    url: 'https://shop.example/',
    finalUrl: 'https://shop.example/',
    auditedAt: '2026-11-08T00:00:00.000Z',
    score: 80,
    grade: 'B',
    counts: { critical: 0, high: 0, medium: 2, low: 4, info: 0 },
    stack: { frameworks: [], hosting: [] },
    metrics: {
      ttfbMs: 100,
      htmlBytes: 0,
      htmlTransferBytes: 0,
      redirects: 0,
      scriptsReferenced: 0,
      stylesheetsReferenced: 0,
      imagesReferenced: 0,
      scriptsScanned: 0,
      jsBytes: 0,
      jsTransferBytes: 0,
    },
    findings: [],
  };

  it('adds the combined score only when both audits worked', () => {
    expect(withLighthouse(base, summarizeLhr(loadLhr('fast'))).combinedScore).toBe(88);
    expect(withLighthouse(base, { error: 'Chrome was not found', durationMs: 1 }).combinedScore).toBeUndefined();
    expect(withLighthouse({ ...base, error: 'ENOTFOUND' }, summarizeLhr(loadLhr('fast'))).combinedScore).toBeUndefined();
  });
});

describe('runLighthouse', () => {
  it('returns an error instead of throwing when the Chrome binary is missing', async () => {
    const result = await runLighthouse('https://shop.example/', { chromePath: '/nonexistent/chrome', timeoutMs: 5_000 });
    expect(result).toMatchObject({ error: expect.stringMatching(/Chrome was not found/) as string });
  });
});

describe('toDatasetItem with Lighthouse', () => {
  const base = withLighthouse(
    {
      url: 'https://shop.example/',
      finalUrl: 'https://shop.example/',
      auditedAt: '2026-11-08T00:00:00.000Z',
      score: 70,
      grade: 'C',
      counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      stack: { frameworks: [], hosting: [] },
      metrics: {
        ttfbMs: 100,
        htmlBytes: 0,
        htmlTransferBytes: 0,
        redirects: 0,
        scriptsReferenced: 0,
        stylesheetsReferenced: 0,
        imagesReferenced: 0,
        scriptsScanned: 0,
        jsBytes: 0,
        jsTransferBytes: 0,
      },
      findings: [],
    },
    summarizeLhr(loadLhr('layout-shift')),
  );

  it('fills the Lighthouse columns and plain-language findings', () => {
    const row = toDatasetItem(base);
    expect(row).toMatchObject({ performance: 7, accessibility: 79, bestPractices: 77, seoScore: 92, lcpMs: 15527, cls: 0.577, tbtMs: 1934, pageKb: 4166, lighthouseError: null });
    expect(row.combinedScore).toBe(base.combinedScore);
    expect(row.hooks).toHaveLength(3);
    expect(row.fixScope).toMatch(/^Fixed-price scope: /);
  });

  it('leaves the columns null and explains why when Lighthouse failed', () => {
    const row = toDatasetItem(withLighthouse(base, { error: 'Lighthouse did not finish within 60 s', durationMs: 60_000 }));
    expect(row).toMatchObject({ performance: null, combinedScore: null, lighthouseError: 'Lighthouse did not finish within 60 s' });
  });
});
