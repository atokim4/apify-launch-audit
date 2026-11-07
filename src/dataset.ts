import type { AuditResult, Finding } from './types.js';

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
  auditedAt: string;
  error: string | null;
}

export function toDatasetItem(r: AuditResult): DatasetItem {
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
    auditedAt: r.auditedAt,
    error: r.error ?? null,
  };
}
