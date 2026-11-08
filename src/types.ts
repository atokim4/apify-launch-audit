export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Category =
  | 'transport'
  | 'headers'
  | 'cookies'
  | 'secrets'
  | 'backend'
  | 'exposure'
  | 'seo'
  | 'performance';

export interface Finding {
  /** Stable machine id, e.g. `headers.csp-missing`. */
  id: string;
  category: Category;
  severity: Severity;
  title: string;
  detail: string;
  fix: string;
  /** Short, already-redacted evidence lines (URLs, header values, masked keys). */
  evidence?: string[];
}

export interface RedirectHop {
  url: string;
  status: number;
  location?: string;
}

export interface Metrics {
  ttfbMs: number | null;
  htmlBytes: number;
  htmlTransferBytes: number;
  redirects: number;
  scriptsReferenced: number;
  stylesheetsReferenced: number;
  imagesReferenced: number;
  scriptsScanned: number;
  jsBytes: number;
  jsTransferBytes: number;
}

export interface Stack {
  frameworks: string[];
  hosting: string[];
}

export interface AuditResult {
  url: string;
  finalUrl: string | null;
  auditedAt: string;
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  counts: Record<Severity, number>;
  stack: Stack;
  metrics: Metrics;
  findings: Finding[];
  /** Set when the site could not be fetched at all. */
  error?: string;
  /** Present only when Lighthouse was requested. */
  lighthouse?: LighthouseSummary | LighthouseFailure;
  /** Security score and Lighthouse scores blended; present only with a successful Lighthouse run. */
  combinedScore?: number;
}

export interface AuditOptions {
  /** Max JS files fetched and scanned per site. */
  maxBundles?: number;
  /** Per-request timeout in milliseconds. */
  timeoutMs?: number;
  /** Max bytes read per response. */
  maxBytes?: number;
  userAgent?: string;
  /** Allow localhost / private IPs. Off by default so a hosted run cannot probe internal networks. */
  allowPrivateNetwork?: boolean;
}

export interface LighthouseScores {
  performance: number | null;
  accessibility: number | null;
  bestPractices: number | null;
  seo: number | null;
}

export interface LighthouseOpportunity {
  /** Lighthouse audit id, e.g. `render-blocking-insight`. */
  id: string;
  title: string;
  /** Estimated LCP/FCP time saved on the simulated phone, in ms. */
  savingsMs: number;
  /** Estimated bytes saved, when Lighthouse reports one. */
  savingsBytes: number;
}

/** The parts of a Lighthouse report (LHR) this tool uses. */
export interface LighthouseSummary {
  lighthouseVersion: string;
  formFactor: string;
  finalUrl: string;
  /** Category scores 0-100; null when Lighthouse could not compute one. */
  scores: LighthouseScores;
  lcpMs: number | null;
  cls: number | null;
  tbtMs: number | null;
  fcpMs: number | null;
  totalKb: number | null;
  jsKb: number | null;
  jsRequests: number | null;
  /** The biggest savings first, at most three. */
  opportunities: LighthouseOpportunity[];
  /** Lighthouse's own warnings (e.g. the page redirected or loaded slowly). */
  warnings: string[];
  durationMs: number;
}

export interface LighthouseFailure {
  error: string;
  durationMs: number;
}
