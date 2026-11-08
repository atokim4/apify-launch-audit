import { describe, expect, it } from 'vitest';
import { buildHooks, type Hook, performanceHooks, pickHooks, scopeLine, securityHooks, workItems } from '../src/hooks.js';
import { summarizeLhr } from '../src/lighthouse/summary.js';
import { toHooksMarkdown } from '../src/report.js';
import type { AuditResult, Finding } from '../src/types.js';
import { loadLhr } from './fixtures/lhr.js';

function finding(id: string, overrides: Partial<Finding> = {}): Finding {
  const category = id.split('.')[0] as Finding['category'];
  return { id, category, severity: 'medium', title: id, detail: '', fix: '', ...overrides };
}

const HEADERS = ['headers.csp-missing', 'headers.clickjacking', 'headers.nosniff-missing', 'transport.hsts-missing'].map((id) => finding(id));

function result(findings: Finding[], lighthouse?: AuditResult['lighthouse']): AuditResult {
  return {
    url: 'https://shop.example/',
    finalUrl: 'https://shop.example/',
    auditedAt: '2026-11-08T00:00:00.000Z',
    score: 70,
    grade: 'C',
    counts: { critical: 0, high: 0, medium: findings.length, low: 0, info: 0 },
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
    findings,
    ...(lighthouse ? { lighthouse } : {}),
  };
}

const hook = (id: string, source: Hook['source'], weight: number): Hook => ({ id, source, weight, sentence: id, scope: id, hours: 1 });

describe('securityHooks', () => {
  it('turns a leaked key into the top hook without repeating the evidence', () => {
    const leak = finding('secrets.stripe-live-secret', {
      category: 'secrets',
      severity: 'critical',
      title: 'Stripe live secret key exposed in client code',
      evidence: ['sk_live_GkUA…[redacted]'],
    });
    const [top] = pickHooks(securityHooks([...HEADERS, leak]));
    expect(top?.id).toBe('secrets.stripe-live-secret');
    expect(top?.sentence).toBe("Stripe live secret key is visible in the site's public JavaScript, so anyone who opens the page can copy it.");
    expect(top?.sentence).not.toContain('sk_live');
  });

  it('groups missing headers into one hook that names only what is really missing', () => {
    const hooks = securityHooks(HEADERS);
    expect(hooks).toHaveLength(1);
    expect(hooks[0]?.sentence).toBe(
      'The server sends only 2 of the 6 standard security headers browsers look for, so nothing stops injected scripts, other sites framing the page or a downgrade to plain http://.',
    );
    const minor = securityHooks([finding('headers.nosniff-missing'), finding('headers.referrer-policy-missing')]);
    expect(minor[0]?.sentence).toBe('The server sends only 4 of the 6 standard security headers browsers look for.');
  });

  it('ignores a single minor header and manual-check notes', () => {
    expect(securityHooks([finding('headers.referrer-policy-missing'), finding('backend.supabase-verify-rls', { severity: 'info' })])).toEqual([]);
  });

  it('uses the real source map count from the title, not the capped evidence list', () => {
    const maps = finding('exposure.source-maps', { title: 'Source maps are public (12)', evidence: ['a.map', 'b.map', 'c.map'] });
    expect(securityHooks([maps])[0]?.sentence).toContain('(12 found)');
  });
});

describe('performanceHooks', () => {
  it('describes a slow page in plain words with the measured numbers', () => {
    const sentences = performanceHooks(summarizeLhr(loadLhr('slow-images'))).map((h) => h.sentence);
    expect(sentences).toContain(
      'Google Lighthouse rates the page 34/100 for speed on a phone: the main content appears after 16.2 s (Google counts under 2.5 s as good).',
    );
    expect(sentences).toContain(
      'This page weighs 21.5 MB on a phone, and its images could be about 15.4 MB smaller with the right size and format, showing the page about 4.5 s sooner.',
    );
    for (const s of sentences) expect(s).not.toMatch(/\b(LCP|TBT|CLS|FCP)\b/);
  });

  it('reports layout shift and a frozen page when they are bad', () => {
    const ids = performanceHooks(summarizeLhr(loadLhr('layout-shift'))).map((h) => h.id);
    expect(ids).toEqual(expect.arrayContaining(['lighthouse.speed', 'lighthouse.layout-shift', 'lighthouse.frozen']));
    expect(performanceHooks(summarizeLhr(loadLhr('frozen'))).find((h) => h.id === 'lighthouse.frozen')?.sentence).toBe(
      'While it loads, the page is frozen for about 5.8 s in total, so taps and scrolls do nothing.',
    );
  });

  it('says nothing about speed for a fast page and skips small savings', () => {
    const hooks = performanceHooks(summarizeLhr(loadLhr('fast')));
    expect(hooks.map((h) => h.id)).toEqual(['lighthouse.render-blocking-insight']);
  });
});

describe('pickHooks', () => {
  it('keeps at least one speed hook when security fills the top three', () => {
    const picked = pickHooks([hook('a', 'security', 100), hook('b', 'security', 95), hook('c', 'security', 90), hook('d', 'performance', 10)]);
    expect(picked.map((h) => h.id)).toEqual(['a', 'b', 'd']);
  });

  it('keeps at least one security hook when speed fills the top three', () => {
    const picked = pickHooks([hook('a', 'performance', 90), hook('b', 'seo', 80), hook('c', 'performance', 70), hook('d', 'security', 40)]);
    expect(picked.map((h) => h.id)).toEqual(['a', 'b', 'd']);
  });

  it('drops a second hook that leads to the same work item', () => {
    const a = { ...hook('a', 'performance', 90), scope: 'split and trim the JavaScript bundles' };
    const b = { ...hook('b', 'performance', 80), scope: 'split and trim the JavaScript bundles' };
    expect(pickHooks([a, b]).map((h) => h.id)).toEqual(['a']);
  });
});

describe('workItems', () => {
  const symptom: Hook = { ...hook('speed', 'performance', 90), scope: null, hours: 0 };

  it('names concrete speed work when only the slow score made the top three', () => {
    const picked = [symptom, hook('sec1', 'security', 80), hook('sec2', 'security', 70)];
    const images = { ...hook('img', 'performance', 50), scope: 'resize and convert the images', hours: 2 };
    expect(workItems(picked, [...picked, images, hook('js', 'performance', 30)]).map((h) => h.scope)).toEqual(['sec1', 'sec2', 'resize and convert the images']);
  });

  it('falls back to a generic speed item when Lighthouse named no specific cause', () => {
    const work = workItems([symptom, hook('sec', 'security', 80)], [symptom]);
    expect(work.at(-1)?.scope).toBe('find and fix what slows the mobile page load');
  });
});

describe('scopeLine', () => {
  it('lists the work, the hours and an optional fixed price', () => {
    const hooks = [
      { ...hook('a', 'security', 1), scope: 'add the missing security headers', hours: 2 },
      { ...hook('b', 'performance', 1), scope: 'resize and convert the images', hours: 2 },
    ];
    expect(scopeLine(hooks)).toBe(
      'Fixed-price scope: add the missing security headers and resize and convert the images; about 4 hours of work, with a before/after re-run of this audit.',
    );
    expect(scopeLine(hooks, 25)).toContain('about 4 hours of work, $100 fixed');
    expect(scopeLine([])).toBeNull();
  });
});

describe('buildHooks + toHooksMarkdown', () => {
  it('mixes security and speed for a real slow page', () => {
    const r = { ...result(HEADERS, summarizeLhr(loadLhr('slow-images'))), combinedScore: 61 };
    const report = buildHooks(r, { hourlyRate: 20 });
    expect(report.hooks).toHaveLength(3);
    expect(report.hooks.map((h) => h.source)).toContain('security');
    const md = toHooksMarkdown(r, report);
    expect(md).toContain('Combined score 61/100 (security 70, mobile speed 34, accessibility 97, best practices 81, SEO 92)');
    expect(md).toMatch(/^1\. Google Lighthouse rates the page 34\/100/m);
    expect(md).toContain(
      'Fixed-price scope: resize and convert the images and add the missing security headers; about 4 hours of work, $80 fixed',
    );
  });

  it('still gives security hooks when Lighthouse failed, and says why speed is missing', () => {
    const r = result(HEADERS, { error: 'Lighthouse did not finish within 60 s', durationMs: 60_000 });
    const md = toHooksMarkdown(r, buildHooks(r));
    expect(md).toContain('Security score 70/100');
    expect(md).toContain('Speed not measured: Lighthouse did not finish within 60 s');
    expect(md).toContain('1. The server sends only 2 of the 6');
  });

  it('says so when there is nothing worth leading with', () => {
    const r = result([], summarizeLhr(loadLhr('fast')));
    const report = buildHooks(r);
    expect(report.hooks.map((h) => h.id)).toEqual(['lighthouse.render-blocking-insight']);
    expect(toHooksMarkdown(result([]), buildHooks(result([])))).toContain('Nothing strong enough to lead with: no serious security issue found.');
  });
});
