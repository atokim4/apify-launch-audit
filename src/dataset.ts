import { buildHooks } from './hooks.js';
import type { AuditResult, Finding, LighthouseFailure, LighthouseSummary } from './types.js';

/** Flat row for the Apify dataset table view; the full result stays in `findings` / `metrics`. */
export interface DatasetItem {
  url: string;
  finalUrl: string | null;
  score: number;
  grade: AuditResult['grade'];
  critical: number;
  high: number;
  medium: number;
  low: number;
  toCheck: number;
  frameworks: string[];
  hosting: string[];
  ttfbMs: number | null;
  jsKb: number;
  topIssues: string[];
  findings: Finding[];
  metrics: AuditResult['metrics'];
  /** Lighthouse columns are null when Lighthouse was off or failed (see `lighthouseError`). */
  combinedScore: number | null;
  performance: number | null;
  accessibility: number | null;
  bestPractices: number | null;
  seoScore: number | null;
  lcpMs: number | null;
  cls: number | null;
  tbtMs: number | null;
  pageKb: number | null;
  /** The strongest findings as plain sentences (security only when Lighthouse was off). */
  hooks: string[];
  fixScope: string | null;
  lighthouse: LighthouseSummary | LighthouseFailure | null;
  lighthouseError: string | null;
  auditedAt: string;
  error: string | null;
}

export function toDatasetItem(r: AuditResult): DatasetItem {
  const lh = r.lighthouse && !('error' in r.lighthouse) ? r.lighthouse : undefined;
  const hooks = buildHooks(r);
  return {
    url: r.url,
    finalUrl: r.finalUrl,
    score: r.score,
    grade: r.grade,
    critical: r.counts.critical,
    high: r.counts.high,
    medium: r.counts.medium,
    low: r.counts.low,
    toCheck: r.counts.info,
    frameworks: r.stack.frameworks,
    hosting: r.stack.hosting,
    ttfbMs: r.metrics.ttfbMs,
    jsKb: Math.round(r.metrics.jsBytes / 1024),
    topIssues: r.findings.filter((f) => f.severity !== 'info').slice(0, 5).map((f) => `${f.severity}: ${f.title}`),
    findings: r.findings,
    metrics: r.metrics,
    combinedScore: r.combinedScore ?? null,
    performance: lh?.scores.performance ?? null,
    accessibility: lh?.scores.accessibility ?? null,
    bestPractices: lh?.scores.bestPractices ?? null,
    seoScore: lh?.scores.seo ?? null,
    lcpMs: lh?.lcpMs ?? null,
    cls: lh?.cls ?? null,
    tbtMs: lh?.tbtMs ?? null,
    pageKb: lh?.totalKb ?? null,
    hooks: hooks.hooks.map((h) => h.sentence),
    fixScope: hooks.scope,
    lighthouse: r.lighthouse ?? null,
    lighthouseError: r.lighthouse && 'error' in r.lighthouse ? r.lighthouse.error : null,
    auditedAt: r.auditedAt,
    error: r.error ?? null,
  };
}
