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
