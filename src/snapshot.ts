import type { HttpResponse } from './http.js';
import type { ScanResult } from './secrets.js';
import type { RedirectHop } from './types.js';

export interface PageInfo {
  title: string | null;
  description: string | null;
  viewport: boolean;
  metaRobots: string | null;
  generator: string | null;
  scripts: string[];
  stylesheets: string[];
  images: number;
  /** http:// subresources on an https page. */
  insecureResources: string[];
  /** Raw HTML, used by stack detection. */
  html: string;
}

export interface BundleInfo {
  url: string;
  bytes: number;
  transferBytes: number;
  compressed: boolean;
  scan: ScanResult;
  /** Framework names detected from runtime markers in this file. */
  frameworkHints: string[];
  /** URL of a source map that was publicly downloadable. */
  publicSourceMap?: string;
}

export interface HttpProbe {
  url: string;
  status?: number;
  location?: string;
  error?: string;
}

/** Everything fetched for one site. Checks are pure functions of this. */
export interface SiteSnapshot {
  inputUrl: string;
  finalUrl: string;
  response: HttpResponse;
  chain: RedirectHop[];
  cookies: { url: string; header: string }[];
  /** The plain-http version of the site, when the audited URL is https. */
  httpProbe?: HttpProbe;
  page: PageInfo | null;
  inlineScan: ScanResult | null;
  bundles: BundleInfo[];
  /** `htmlFallback`: the server answered with an HTML page (typical SPA catch-all) instead of a robots file. */
  robots: { status: number; text: string; htmlFallback: boolean } | null;
  sitemap: { url: string; found: boolean } | null;
  exposedFiles: { path: string; url: string }[];
}
