import type { LighthouseOpportunity, LighthouseScores, LighthouseSummary } from '../types.js';

/**
 * The subset of a Lighthouse result (LHR) that `summarizeLhr` reads. Kept structural so trimmed
 * fixtures and full reports from `lighthouse` 13.x both fit.
 */
export interface LhrAudit {
  id: string;
  title: string;
  score: number | null;
  scoreDisplayMode?: string;
  numericValue?: number;
  numericUnit?: string;
  metricSavings?: Record<string, number | undefined>;
  details?: {
    type?: string;
    overallSavingsMs?: number;
    overallSavingsBytes?: number;
    items?: unknown[];
  };
}

export interface LhrLike {
  lighthouseVersion: string;
  finalDisplayedUrl?: string;
  configSettings?: { formFactor?: string };
  categories: Record<string, { score: number | null; auditRefs?: { id: string; group?: string }[] } | undefined>;
  audits: Record<string, LhrAudit | undefined>;
  runWarnings?: string[];
  runtimeError?: { code: string; message: string };
}

const MAX_OPPORTUNITIES = 3;
/** Savings below these are noise on a simulated phone run. */
const MIN_SAVINGS_MS = 100;
const MIN_SAVINGS_BYTES = 20 * 1024;
/** Audits that describe a symptom, not a fix, or overlap with the passive checks. */
const NOT_ACTIONABLE = new Set(['network-dependency-tree-insight', 'lcp-breakdown-insight', 'inp-breakdown-insight']);

const toScore = (value: number | null | undefined): number | null =>
  typeof value === 'number' ? Math.round(value * 100) : null;

function metric(lhr: LhrLike, id: string): number | null {
  const value = lhr.audits[id]?.numericValue;
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

const roundMs = (value: number | null): number | null => (value === null ? null : Math.round(value));
const toKb = (bytes: number | undefined): number | null => (typeof bytes === 'number' ? Math.round(bytes / 1024) : null);

interface ResourceRow {
  resourceType: string;
  requestCount: number;
  transferSize: number;
}

function isResourceRow(item: unknown): item is ResourceRow {
  if (typeof item !== 'object' || item === null) return false;
  const row = item as Record<string, unknown>;
  return typeof row.resourceType === 'string' && typeof row.transferSize === 'number' && typeof row.requestCount === 'number';
}

function resources(lhr: LhrLike): Map<string, ResourceRow> {
  const rows = (lhr.audits['resource-summary']?.details?.items ?? []).filter(isResourceRow);
  return new Map(rows.map((r) => [r.resourceType, r]));
}

function savingsOf(audit: LhrAudit): { savingsMs: number; savingsBytes: number } {
  const ms = Math.max(audit.metricSavings?.LCP ?? 0, audit.metricSavings?.FCP ?? 0, audit.details?.overallSavingsMs ?? 0);
  const bytes = audit.details?.overallSavingsBytes ?? (audit.numericUnit === 'byte' ? (audit.numericValue ?? 0) : 0);
  return { savingsMs: Math.round(ms), savingsBytes: Math.round(bytes) };
}

/** Failed performance audits with a real estimated saving, biggest time saving first, then bytes. */
export function topOpportunities(lhr: LhrLike, limit = MAX_OPPORTUNITIES): LighthouseOpportunity[] {
  const refs = lhr.categories.performance?.auditRefs ?? [];
  const candidates: LighthouseOpportunity[] = [];
  for (const ref of refs) {
    const audit = lhr.audits[ref.id];
    if (!audit || NOT_ACTIONABLE.has(audit.id) || ref.group === 'metrics' || ref.group === 'hidden') continue;
    if (audit.score === null || audit.score >= 0.9) continue;
    const { savingsMs, savingsBytes } = savingsOf(audit);
    if (savingsMs < MIN_SAVINGS_MS && savingsBytes < MIN_SAVINGS_BYTES) continue;
    candidates.push({ id: audit.id, title: audit.title, savingsMs, savingsBytes });
  }
  return candidates
    .sort((a, b) => b.savingsMs - a.savingsMs || b.savingsBytes - a.savingsBytes)
    .slice(0, limit);
}

/** Turns a Lighthouse report into the numbers this tool reports. Throws on a runtime error report. */
export function summarizeLhr(lhr: LhrLike, durationMs = 0): LighthouseSummary {
  if (lhr.runtimeError) throw new Error(`Lighthouse: ${lhr.runtimeError.code} ${lhr.runtimeError.message}`);
  const scores: LighthouseScores = {
    performance: toScore(lhr.categories.performance?.score),
    accessibility: toScore(lhr.categories.accessibility?.score),
    bestPractices: toScore(lhr.categories['best-practices']?.score),
    seo: toScore(lhr.categories.seo?.score),
  };
  const rows = resources(lhr);
  const cls = metric(lhr, 'cumulative-layout-shift');
  return {
    lighthouseVersion: lhr.lighthouseVersion,
    formFactor: lhr.configSettings?.formFactor ?? 'mobile',
    finalUrl: lhr.finalDisplayedUrl ?? '',
    scores,
    lcpMs: roundMs(metric(lhr, 'largest-contentful-paint')),
    cls: cls === null ? null : Math.round(cls * 1000) / 1000,
    tbtMs: roundMs(metric(lhr, 'total-blocking-time')),
    fcpMs: roundMs(metric(lhr, 'first-contentful-paint')),
    totalKb: toKb(rows.get('total')?.transferSize),
    jsKb: toKb(rows.get('script')?.transferSize),
    jsRequests: rows.get('script')?.requestCount ?? null,
    opportunities: topOpportunities(lhr),
    warnings: lhr.runWarnings ?? [],
    durationMs,
  };
}
