import type { SiteSnapshot } from '../snapshot.js';
import type { Finding } from '../types.js';

export interface ParsedCookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
}

export function parseSetCookie(header: string): ParsedCookie {
  const [pair = '', ...attrs] = header.split(';');
  const name = pair.split('=')[0]?.trim() ?? '';
  const lower = attrs.map((a) => a.trim().toLowerCase());
  const sameSite = lower.find((a) => a.startsWith('samesite='))?.split('=')[1]?.trim() ?? null;
  return {
    name,
    secure: lower.includes('secure'),
    httpOnly: lower.includes('httponly'),
    sameSite,
  };
}

const SESSION_NAME = /sess|sid\b|^sid|token|auth|jwt|login|remember|connect\.sid|csrf/i;

/** Analytics / fraud-detection cookies that are JS-readable by design. */
const TRACKING_NAME = /^(_ga|_gid|_gcl|ajs_|_fbp|_fbc|_hj|mp_|amp_|__stripe_|_clck|_clsk|_uet|intercom-|__hs|hubspot|_pk_|ph_|_dd_s|_tt_|optimizely)/i;

const isSessionLike = (name: string): boolean => SESSION_NAME.test(name) && !TRACKING_NAME.test(name);

export function checkCookies(s: SiteSnapshot): Finding[] {
  const isHttps = s.finalUrl.startsWith('https://');
  const byName = new Map<string, ParsedCookie>();
  for (const { header } of s.cookies) {
    const c = parseSetCookie(header);
    if (c.name) byName.set(c.name, c);
  }
  const cookies = [...byName.values()];
  const findings: Finding[] = [];

  const notSecure = isHttps ? cookies.filter((c) => !c.secure) : [];
  if (notSecure.length > 0) {
    findings.push({
      id: 'cookies.secure-missing',
      category: 'cookies',
      severity: 'medium',
      title: `${notSecure.length} cookie(s) without the Secure flag`,
      detail: 'These cookies can be sent over plain HTTP and read by anyone on the network path.',
      fix: 'Add `Secure` to every cookie on an HTTPS site.',
      evidence: notSecure.map((c) => c.name),
    });
  }

  const sessionReadable = cookies.filter((c) => isSessionLike(c.name) && !c.httpOnly);
  if (sessionReadable.length > 0) {
    findings.push({
      id: 'cookies.httponly-missing',
      category: 'cookies',
      severity: 'medium',
      title: 'Session-like cookie readable from JavaScript',
      detail: 'Without HttpOnly, any XSS can steal the session cookie.',
      fix: 'Set `HttpOnly` on session and auth cookies (CSRF tokens read by your own JS are the exception).',
      evidence: sessionReadable.map((c) => c.name),
    });
  }

  const noneInsecure = cookies.filter((c) => c.sameSite === 'none' && !c.secure);
  if (noneInsecure.length > 0) {
    findings.push({
      id: 'cookies.samesite-none-insecure',
      category: 'cookies',
      severity: 'medium',
      title: 'SameSite=None cookie without Secure',
      detail: 'Browsers reject SameSite=None cookies that are not Secure, so these cookies silently stop working.',
      fix: 'Add `Secure` or switch to `SameSite=Lax`.',
      evidence: noneInsecure.map((c) => c.name),
    });
  }

  const noSameSite = cookies.filter((c) => c.sameSite === null && isSessionLike(c.name));
  if (noSameSite.length > 0) {
    findings.push({
      id: 'cookies.samesite-missing',
      category: 'cookies',
      severity: 'low',
      title: 'Session-like cookie without SameSite',
      detail: 'Browsers default to Lax, but an explicit value documents intent and protects older browsers against CSRF.',
      fix: 'Set `SameSite=Lax` (or Strict) on session cookies.',
      evidence: noSameSite.map((c) => c.name),
    });
  }

  return findings;
}
