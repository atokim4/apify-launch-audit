import { checkCookies } from './checks/cookies.js';
import { checkHeaders } from './checks/headers.js';
import { checkPerformance, collectMetrics } from './checks/performance.js';
import { checkSecrets } from './checks/secrets.js';
import { checkSeo } from './checks/seo.js';
import { bundleHints, checkStack, detectStack } from './checks/stack.js';
import { checkTransport } from './checks/transport.js';
import {
  createFetcher,
  FetchError,
  type Fetcher,
  followRedirects,
  type HttpResponse,
  isHtml,
  isTlsError,
  type RedirectResult,
  textOf,
} from './http.js';
import { chunkReferences, isFirstParty, parsePage } from './page.js';
import { countBySeverity, grade, score, sortFindings } from './score.js';
import { scanText } from './secrets.js';
import type { BundleInfo, HttpProbe, SiteSnapshot } from './snapshot.js';
import type { AuditOptions, AuditResult, Finding } from './types.js';

export const DEFAULTS = {
  maxBundles: 20,
  timeoutMs: 15_000,
  maxBytes: 8 * 1024 * 1024,
  userAgent: 'launch-audit/0.1 (+passive pre-launch checks)',
  allowPrivateNetwork: false,
} satisfies Required<AuditOptions>;

const BUNDLE_CONCURRENCY = 4;
/** Probes (robots, sitemap, source maps, dotfiles) only need the start of the file. */
const PROBE_BYTES = 64 * 1024;
const SOURCE_MAP_GUESSES = 3;

/** Adds https:// to bare domains and rejects anything that is not http(s). */
export function normalizeUrl(input: string): string {
  const trimmed = input.trim();
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  const url = new URL(withScheme);
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new Error(`unsupported protocol ${url.protocol}`);
  }
  url.hash = '';
  return url.toString();
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next++;
      results[index] = await fn(items[index] as T);
    }
  });
  await Promise.all(workers);
  return results;
}

async function tryFetch(fetcher: Fetcher, url: string, maxBytes?: number): Promise<HttpResponse | null> {
  try {
    return await fetcher(url, maxBytes);
  } catch {
    return null;
  }
}

function looksLikeSourceMap(res: HttpResponse | null): boolean {
  if (!res || res.status !== 200) return false;
  const text = textOf(res);
  return /^\s*\{/.test(text) && text.includes('"version"') && /"(mappings|sources)"/.test(text);
}

async function findPublicSourceMap(
  fetcher: Fetcher,
  bundle: HttpResponse,
  js: string,
  guess: boolean,
): Promise<string | undefined> {
  const comment = /\/\/[#@]\s*sourceMappingURL=(\S+)\s*$/.exec(js.slice(-500))?.[1];
  const declared = comment && !comment.startsWith('data:') ? comment : (bundle.headers.sourcemap ?? bundle.headers['x-sourcemap']);
  let candidate: string | undefined;
  try {
    candidate = declared ? new URL(declared, bundle.url).toString() : guess ? `${bundle.url}.map` : undefined;
  } catch {
    return undefined; // malformed sourceMappingURL
  }
  if (!candidate) return undefined;
  return looksLikeSourceMap(await tryFetch(fetcher, candidate, PROBE_BYTES)) ? candidate : undefined;
}

async function scanBundles(fetcher: Fetcher, pageUrl: string, scripts: string[], max: number): Promise<BundleInfo[]> {
  const seen = new Set<string>();
  const queue: string[] = [];
  const enqueue = (url: string): void => {
    const clean = url.split('#')[0] ?? url;
    if (seen.has(clean) || !isFirstParty(clean, pageUrl)) return;
    seen.add(clean);
    queue.push(clean);
  };
  scripts.forEach(enqueue);

  const bundles: BundleInfo[] = [];
  while (queue.length > 0 && bundles.length < max) {
    const batch = queue.splice(0, Math.min(BUNDLE_CONCURRENCY, max - bundles.length));
    const fetched = await mapLimit(batch, BUNDLE_CONCURRENCY, async (url) => {
      const res = await tryFetch(fetcher, url);
      if (!res || res.status !== 200 || isHtml(res)) return null;
      const js = textOf(res);
      const publicSourceMap = await findPublicSourceMap(fetcher, res, js, bundles.length < SOURCE_MAP_GUESSES);
      chunkReferences(js, url).forEach(enqueue);
      const info: BundleInfo = {
        url,
        bytes: res.body.length,
        transferBytes: res.transferBytes,
        compressed: !!res.headers['content-encoding'],
        scan: scanText(js),
        frameworkHints: bundleHints(js),
        ...(publicSourceMap ? { publicSourceMap } : {}),
      };
      return info;
    });
    for (const b of fetched) if (b) bundles.push(b);
  }
  return bundles;
}

async function probeHttp(fetcher: Fetcher, httpsUrl: string): Promise<HttpProbe> {
  const url = new URL(httpsUrl);
  url.protocol = 'http:';
  url.pathname = '/';
  url.search = '';
  const target = url.toString();
  try {
    const res = await fetcher(target, PROBE_BYTES);
    const location = res.headers.location ? new URL(res.headers.location, target).toString() : undefined;
    return { url: target, status: res.status, ...(location ? { location } : {}) };
  } catch (err) {
    return { url: target, error: (err as Error).message };
  }
}

async function probeExposedFiles(fetcher: Fetcher, origin: string): Promise<SiteSnapshot['exposedFiles']> {
  const probes = [
    { path: '/.env', valid: (t: string) => /^\s*[A-Z][A-Z0-9_]*\s*=/m.test(t) },
    { path: '/.git/HEAD', valid: (t: string) => /^ref: refs\/heads\//.test(t) },
  ];
  const results = await Promise.all(
    probes.map(async (p) => {
      const url = new URL(p.path, origin).toString();
      const res = await tryFetch(fetcher, url, PROBE_BYTES);
      return res && res.status === 200 && !isHtml(res) && p.valid(textOf(res).slice(0, 2000)) ? { path: p.path, url } : null;
    }),
  );
  return results.filter((r) => r !== null);
}

async function fetchRobotsAndSitemap(
  fetcher: Fetcher,
  origin: string,
): Promise<Pick<SiteSnapshot, 'robots' | 'sitemap'>> {
  const robotsRes = await tryFetch(fetcher, new URL('/robots.txt', origin).toString(), PROBE_BYTES);
  const robots = robotsRes
    ? isHtml(robotsRes)
      ? { status: robotsRes.status, text: '', htmlFallback: true }
      : { status: robotsRes.status, text: robotsRes.status === 200 ? textOf(robotsRes) : '', htmlFallback: false }
    : null;
  const declared = robots ? /^\s*sitemap:\s*(\S+)/im.exec(robots.text)?.[1] : undefined;
  const sitemapUrl = declared ? new URL(declared, origin).toString() : new URL('/sitemap.xml', origin).toString();
  const sitemapRes = await tryFetch(fetcher, sitemapUrl, PROBE_BYTES);
  const found = !!sitemapRes && sitemapRes.status === 200 && /<(urlset|sitemapindex)[\s>]/.test(textOf(sitemapRes).slice(0, 5000));
  return { robots, sitemap: { url: sitemapUrl, found } };
}

function tlsFinding(url: string, err: FetchError): Finding {
  return {
    id: 'transport.tls-invalid',
    category: 'transport',
    severity: 'critical',
    title: 'HTTPS certificate is not valid',
    detail: `Browsers show a full-page warning for ${url} (${err.code ?? err.message}).`,
    fix: 'Renew or reissue the certificate for this exact hostname (Let’s Encrypt or the host’s managed TLS) and include the full chain.',
  };
}

async function loadMain(
  fetcher: Fetcher,
  url: string,
  hadScheme: boolean,
): Promise<{ main: RedirectResult; extra: Finding[] }> {
  try {
    return { main: await followRedirects(fetcher, url), extra: [] };
  } catch (err) {
    const canFallBack = url.startsWith('https://') && (isTlsError(err) || !hadScheme);
    if (!canFallBack) throw err;
    const httpUrl = url.replace(/^https:/, 'http:');
    try {
      const main = await followRedirects(fetcher, httpUrl);
      return { main, extra: isTlsError(err) ? [tlsFinding(url, err as FetchError)] : [] };
    } catch {
      // http:// usually redirects back to the broken https://; report the original error.
      throw err;
    }
  }
}

export async function collectSnapshot(
  input: string,
  options: AuditOptions = {},
  fetcher?: Fetcher,
): Promise<{ snapshot: SiteSnapshot; extra: Finding[] }> {
  const opts = { ...DEFAULTS, ...options };
  const fetch = fetcher ?? createFetcher(opts);
  const hadScheme = /^https?:\/\//i.test(input.trim());
  const startUrl = normalizeUrl(input);

  const { main, extra } = await loadMain(fetch, startUrl, hadScheme);
  const response = main.response;
  const finalUrl = response.url;
  const origin = new URL(finalUrl).origin;

  const page = isHtml(response) ? parsePage(textOf(response), finalUrl) : null;
  // When the input was http://, its first redirect hop already is the http probe.
  const firstHop = main.chain[0];
  const hopProbe: HttpProbe | undefined = firstHop?.url.startsWith('http://')
    ? { url: firstHop.url, status: firstHop.status, ...(firstHop.location ? { location: firstHop.location } : {}) }
    : undefined;
  const needsProbe = finalUrl.startsWith('https://') && !hopProbe;

  const [httpProbe, exposedFiles, crawl, bundles] = await Promise.all([
    needsProbe ? probeHttp(fetch, finalUrl) : Promise.resolve(hopProbe),
    probeExposedFiles(fetch, origin),
    fetchRobotsAndSitemap(fetch, origin),
    scanBundles(fetch, finalUrl, page?.scripts ?? [], opts.maxBundles),
  ]);

  const snapshot: SiteSnapshot = {
    inputUrl: startUrl,
    finalUrl,
    response,
    chain: main.chain,
    cookies: main.cookies,
    ...(httpProbe ? { httpProbe } : {}),
    page,
    inlineScan: page ? scanText(page.html) : null,
    bundles,
    ...crawl,
    exposedFiles,
  };
  return { snapshot, extra };
}

export function evaluate(snapshot: SiteSnapshot, extra: Finding[] = []): AuditResult {
  const metrics = collectMetrics(snapshot);
  const findings = sortFindings([
    ...extra,
    ...checkTransport(snapshot),
    ...checkHeaders(snapshot),
    ...checkCookies(snapshot),
    ...checkSecrets(snapshot),
    ...checkStack(snapshot),
    ...checkSeo(snapshot),
    ...checkPerformance(snapshot, metrics),
  ]);
  const value = score(findings);
  return {
    url: snapshot.inputUrl,
    finalUrl: snapshot.finalUrl,
    auditedAt: new Date().toISOString(),
    score: value,
    grade: grade(value),
    counts: countBySeverity(findings),
    stack: detectStack(snapshot),
    metrics,
    findings,
  };
}

const EMPTY_METRICS: AuditResult['metrics'] = {
  ttfbMs: null,
  htmlBytes: 0,
  htmlTransferBytes: 0,
  redirects: 0,
  scriptsReferenced: 0,
  stylesheetsReferenced: 0,
  imagesReferenced: 0,
  scriptsScanned: 0,
  jsBytes: 0,
  jsTransferBytes: 0,
};

/** Audits one site. Never throws: an unreachable site comes back with `error` set and score 0. */
export async function auditSite(input: string, options: AuditOptions = {}, fetcher?: Fetcher): Promise<AuditResult> {
  try {
    const { snapshot, extra } = await collectSnapshot(input, options, fetcher);
    return evaluate(snapshot, extra);
  } catch (err) {
    let url = input;
    try {
      url = normalizeUrl(input);
    } catch {
      // keep the raw input
    }
    // A broken certificate is itself the most important finding, even if nothing else loads.
    const findings = isTlsError(err) ? [tlsFinding(url, err as FetchError)] : [];
    return {
      url,
      finalUrl: null,
      auditedAt: new Date().toISOString(),
      score: 0,
      grade: 'F',
      counts: countBySeverity(findings),
      stack: { frameworks: [], hosting: [] },
      metrics: EMPTY_METRICS,
      findings,
      error: (err as Error).message,
    };
  }
}
