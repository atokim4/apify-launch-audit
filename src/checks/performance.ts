import type { SiteSnapshot } from '../snapshot.js';
import type { Finding, Metrics } from '../types.js';

const KB = 1024;

export function collectMetrics(s: SiteSnapshot): Metrics {
  return {
    ttfbMs: s.response.ttfbMs,
    htmlBytes: s.response.body.length,
    htmlTransferBytes: s.response.transferBytes,
    redirects: s.chain.length,
    scriptsReferenced: s.page?.scripts.length ?? 0,
    stylesheetsReferenced: s.page?.stylesheets.length ?? 0,
    imagesReferenced: s.page?.images ?? 0,
    scriptsScanned: s.bundles.length,
    jsBytes: s.bundles.reduce((sum, b) => sum + b.bytes, 0),
    jsTransferBytes: s.bundles.reduce((sum, b) => sum + b.transferBytes, 0),
  };
}

export function checkPerformance(s: SiteSnapshot, m: Metrics): Finding[] {
  const findings: Finding[] = [];

  if (m.ttfbMs !== null && m.ttfbMs > 800) {
    findings.push({
      id: 'performance.slow-ttfb',
      category: 'performance',
      severity: m.ttfbMs > 1800 ? 'medium' : 'low',
      title: `Slow server response (TTFB ${m.ttfbMs} ms)`,
      detail: 'Measured from the audit server for the final HTML document; Google rates under 800 ms as good.',
      fix: 'Cache the HTML at the edge/CDN, pre-render static pages, and check slow database calls in the page handler.',
    });
  }

  if (m.jsBytes > 1000 * KB) {
    findings.push({
      id: 'performance.heavy-js',
      category: 'performance',
      severity: m.jsBytes > 2500 * KB ? 'medium' : 'low',
      title: `Heavy JavaScript: ${Math.round(m.jsBytes / KB)} KB uncompressed in ${m.scriptsScanned} file(s)`,
      detail: 'Large bundles delay interactivity, especially on mid-range phones.',
      fix: 'Code-split routes (dynamic import), drop unused dependencies, and check the bundle with a visualizer (rollup-plugin-visualizer, @next/bundle-analyzer).',
    });
  }

  const uncompressed: string[] = [];
  if (!s.response.headers['content-encoding'] && m.htmlBytes > 10 * KB) uncompressed.push(s.finalUrl);
  for (const b of s.bundles) if (!b.compressed && b.bytes > 10 * KB) uncompressed.push(b.url);
  if (uncompressed.length > 0) {
    findings.push({
      id: 'performance.no-compression',
      category: 'performance',
      severity: 'low',
      title: 'Text responses are not compressed',
      detail: 'The server ignored `Accept-Encoding: gzip, br` for these files.',
      fix: 'Enable Brotli or gzip at the server/CDN for HTML, JS, CSS and JSON.',
      evidence: uncompressed.slice(0, 5),
    });
  }

  return findings;
}
