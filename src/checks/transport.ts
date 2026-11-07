import type { SiteSnapshot } from '../snapshot.js';
import type { Finding } from '../types.js';

const HALF_YEAR = 15_552_000;

export function checkTransport(s: SiteSnapshot): Finding[] {
  const findings: Finding[] = [];
  const final = new URL(s.finalUrl);

  if (final.protocol !== 'https:') {
    findings.push({
      id: 'transport.no-https',
      category: 'transport',
      severity: 'high',
      title: 'Site is served over plain HTTP',
      detail: `The final page ${s.finalUrl} is not encrypted. Logins, cookies and API keys travel in clear text.`,
      fix: 'Serve the site over HTTPS (all major hosts issue free certificates) and redirect http:// to https://.',
    });
    return findings;
  }

  const probe = s.httpProbe;
  if (probe && !probe.error && probe.status !== undefined) {
    const upgrades = probe.location?.startsWith('https://') ?? false;
    if (!upgrades) {
      findings.push({
        id: 'transport.no-http-redirect',
        category: 'transport',
        severity: 'medium',
        title: 'http:// does not redirect to https://',
        detail: `${probe.url} answered ${probe.status}${probe.location ? ` → ${probe.location}` : ''} instead of redirecting to HTTPS.`,
        fix: 'Add a permanent (301/308) redirect from http:// to https:// at the host or CDN.',
      });
    } else if (probe.status !== 301 && probe.status !== 308) {
      findings.push({
        id: 'transport.temporary-redirect',
        category: 'transport',
        severity: 'low',
        title: 'HTTP → HTTPS redirect is temporary',
        detail: `${probe.url} uses ${probe.status}; browsers and search engines will not cache it.`,
        fix: 'Use 301 or 308 for the HTTPS upgrade.',
      });
    }
  }

  if (s.chain.length > 2) {
    findings.push({
      id: 'transport.redirect-chain',
      category: 'performance',
      severity: 'low',
      title: `Redirect chain of ${s.chain.length} hops`,
      detail: 'Each hop adds a round trip before the first byte of the page.',
      fix: 'Point links and DNS straight at the final URL so the browser lands in one hop.',
      evidence: s.chain.map((h) => `${h.status} ${h.url} → ${h.location ?? ''}`),
    });
  }

  const hsts = s.response.headers['strict-transport-security'];
  if (!hsts) {
    findings.push({
      id: 'transport.hsts-missing',
      category: 'transport',
      severity: 'medium',
      title: 'No Strict-Transport-Security header',
      detail: 'Without HSTS a first visit over http:// can be intercepted before the redirect.',
      fix: 'Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS responses.',
    });
  } else {
    const maxAge = Number(/max-age\s*=\s*"?(\d+)/i.exec(hsts)?.[1] ?? 0);
    if (maxAge < HALF_YEAR) {
      findings.push({
        id: 'transport.hsts-short',
        category: 'transport',
        severity: 'low',
        title: 'HSTS max-age is shorter than 6 months',
        detail: `Current value: ${hsts}`,
        fix: 'Raise max-age to at least 15552000 (180 days); 31536000 is the common choice.',
        evidence: [hsts],
      });
    }
  }

  if (s.page && s.page.insecureResources.length > 0) {
    findings.push({
      id: 'transport.mixed-content',
      category: 'transport',
      severity: 'medium',
      title: 'Mixed content: page loads http:// resources',
      detail: 'Browsers block or warn about insecure scripts, styles and images on an HTTPS page.',
      fix: 'Load these resources over https:// (or a protocol-relative/self-hosted copy).',
      evidence: s.page.insecureResources.slice(0, 10),
    });
  }

  return findings;
}
