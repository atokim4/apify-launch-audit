import type { SiteSnapshot } from '../snapshot.js';
import type { Finding } from '../types.js';

function directive(csp: string, name: string): string | null {
  for (const part of csp.split(';')) {
    const [key, ...values] = part.trim().split(/\s+/);
    if (key?.toLowerCase() === name) return values.join(' ');
  }
  return null;
}

export function checkHeaders(s: SiteSnapshot): Finding[] {
  const h = s.response.headers;
  const findings: Finding[] = [];
  const csp = h['content-security-policy'];

  if (!csp) {
    findings.push({
      id: 'headers.csp-missing',
      category: 'headers',
      severity: 'medium',
      title: 'No Content-Security-Policy',
      detail: 'A CSP limits what an injected script can load or send, and is the main defence-in-depth against XSS.',
      fix: "Start with `Content-Security-Policy: default-src 'self'; frame-ancestors 'self'` plus the API/CDN origins the app needs, test with Content-Security-Policy-Report-Only first.",
    });
  } else {
    const scriptSrc = directive(csp, 'script-src') ?? directive(csp, 'default-src') ?? '';
    if (scriptSrc.includes("'unsafe-inline'") && !/'nonce-|'sha(256|384|512)-|'strict-dynamic'/.test(scriptSrc)) {
      findings.push({
        id: 'headers.csp-unsafe-inline',
        category: 'headers',
        severity: 'low',
        title: "CSP allows 'unsafe-inline' scripts",
        detail: 'Inline scripts are allowed without a nonce or hash, so the policy does not stop most XSS.',
        fix: "Replace 'unsafe-inline' with per-request nonces or script hashes (Next.js and Nuxt both support nonces).",
        evidence: [`script-src ${scriptSrc}`],
      });
    }
  }

  const frameAncestors = csp ? directive(csp, 'frame-ancestors') : null;
  if (!h['x-frame-options'] && frameAncestors === null) {
    findings.push({
      id: 'headers.clickjacking',
      category: 'headers',
      severity: 'medium',
      title: 'Page can be framed by any site (clickjacking)',
      detail: 'Neither X-Frame-Options nor CSP frame-ancestors is set.',
      fix: "Send `X-Frame-Options: DENY` (or SAMEORIGIN) or add `frame-ancestors 'self'` to the CSP.",
    });
  }

  if ((h['x-content-type-options'] ?? '').toLowerCase().trim() !== 'nosniff') {
    findings.push({
      id: 'headers.nosniff-missing',
      category: 'headers',
      severity: 'low',
      title: 'X-Content-Type-Options: nosniff is missing',
      detail: 'Browsers may MIME-sniff uploads or API responses into executable content.',
      fix: 'Send `X-Content-Type-Options: nosniff` on every response.',
    });
  }

  if (!h['referrer-policy']) {
    findings.push({
      id: 'headers.referrer-policy-missing',
      category: 'headers',
      severity: 'low',
      title: 'No Referrer-Policy',
      detail: 'Full URLs (including tokens in query strings) can leak to third-party sites via the Referer header.',
      fix: 'Send `Referrer-Policy: strict-origin-when-cross-origin`.',
    });
  }

  if (!h['permissions-policy']) {
    findings.push({
      id: 'headers.permissions-policy-missing',
      category: 'headers',
      severity: 'low',
      title: 'No Permissions-Policy',
      detail: 'Embedded third-party code can request camera, microphone or geolocation.',
      fix: 'Send e.g. `Permissions-Policy: camera=(), microphone=(), geolocation=()` and allow only what the app uses.',
    });
  }

  const disclosed = [h['x-powered-by'], h.server].filter((v): v is string => !!v && /\d+\.\d+/.test(v));
  if (disclosed.length > 0) {
    findings.push({
      id: 'headers.version-disclosure',
      category: 'headers',
      severity: 'low',
      title: 'Server software version is disclosed',
      detail: 'Exact versions make it easy to match the server against known CVEs.',
      fix: 'Remove X-Powered-By and the version from the Server header (e.g. `server_tokens off` in nginx, `app.disable("x-powered-by")` in Express).',
      evidence: disclosed,
    });
  }

  return findings;
}
