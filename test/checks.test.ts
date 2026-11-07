import { describe, expect, it } from 'vitest';
import { normalizeUrl } from '../src/audit.js';
import { checkCookies, parseSetCookie } from '../src/checks/cookies.js';
import { checkHeaders } from '../src/checks/headers.js';
import { blocksEverything, checkSeo } from '../src/checks/seo.js';
import { checkTransport } from '../src/checks/transport.js';
import { followRedirects, type HttpResponse } from '../src/http.js';
import { chunkReferences, isFirstParty, siteKey } from '../src/page.js';
import { grade, score } from '../src/score.js';
import type { SiteSnapshot } from '../src/snapshot.js';
import type { Finding } from '../src/types.js';

function response(url: string, status = 200, headers: Record<string, string> = {}): HttpResponse {
  return { url, status, headers, setCookies: [], body: Buffer.from(''), transferBytes: 0, ttfbMs: 10, truncated: false };
}

function snapshot(overrides: Partial<SiteSnapshot> = {}): SiteSnapshot {
  const finalUrl = overrides.finalUrl ?? 'https://app.example.com/';
  return {
    inputUrl: finalUrl,
    finalUrl,
    response: response(finalUrl),
    chain: [],
    cookies: [],
    page: null,
    inlineScan: null,
    bundles: [],
    robots: null,
    sitemap: null,
    exposedFiles: [],
    ...overrides,
  };
}

const ids = (findings: Finding[]): string[] => findings.map((f) => f.id);

describe('checkTransport', () => {
  const hsts = { 'strict-transport-security': 'max-age=31536000; includeSubDomains' };

  it('passes a site with a permanent upgrade and long HSTS', () => {
    const s = snapshot({
      response: response('https://app.example.com/', 200, hsts),
      httpProbe: { url: 'http://app.example.com/', status: 301, location: 'https://app.example.com/' },
    });
    expect(checkTransport(s)).toEqual([]);
  });

  it('flags http that serves content, temporary redirects and short HSTS', () => {
    expect(ids(checkTransport(snapshot({ httpProbe: { url: 'http://a/', status: 200 } })))).toContain('transport.no-http-redirect');
    const temp = snapshot({
      response: response('https://app.example.com/', 200, { 'strict-transport-security': 'max-age=300' }),
      httpProbe: { url: 'http://a/', status: 302, location: 'https://app.example.com/' },
    });
    expect(ids(checkTransport(temp))).toEqual(['transport.temporary-redirect', 'transport.hsts-short']);
  });

  it('does not judge the http redirect when the probe failed', () => {
    const s = snapshot({ response: response('https://a.example/', 200, hsts), httpProbe: { url: 'http://a/', error: 'ECONNREFUSED' } });
    expect(checkTransport(s)).toEqual([]);
  });
});

describe('checkHeaders', () => {
  it('accepts CSP frame-ancestors instead of X-Frame-Options', () => {
    const s = snapshot({
      response: response('https://a.example/', 200, {
        'content-security-policy': "default-src 'self'; script-src 'self' 'nonce-abc' 'unsafe-inline'; frame-ancestors 'none'",
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        'permissions-policy': 'camera=()',
        server: 'cloudflare',
      }),
    });
    expect(checkHeaders(s)).toEqual([]);
  });

  it("flags 'unsafe-inline' without nonce and version numbers", () => {
    const s = snapshot({
      response: response('https://a.example/', 200, {
        'content-security-policy': "script-src 'self' 'unsafe-inline'",
        'x-powered-by': 'PHP/8.1.2',
      }),
    });
    expect(ids(checkHeaders(s))).toEqual(
      expect.arrayContaining(['headers.csp-unsafe-inline', 'headers.clickjacking', 'headers.version-disclosure']),
    );
  });
});

describe('cookies', () => {
  it('parses flags case-insensitively', () => {
    expect(parseSetCookie('sid=1; path=/; SECURE; httponly; SameSite=None')).toEqual({
      name: 'sid',
      secure: true,
      httpOnly: true,
      sameSite: 'none',
    });
  });

  it('only demands HttpOnly for session-like names, and Secure for all on https', () => {
    const s = snapshot({
      cookies: [
        { url: 'https://a/', header: 'auth_token=x; Path=/; Secure' },
        { url: 'https://a/', header: 'theme=dark; Path=/; SameSite=Lax' },
        { url: 'https://a/', header: 'ajs_session_id=1; Path=/; Secure; SameSite=Strict' },
        { url: 'https://a/', header: '__stripe_sid=1; Path=/; Secure' },
      ],
    });
    const findings = checkCookies(s);
    expect(findings.find((f) => f.id === 'cookies.httponly-missing')?.evidence).toEqual(['auth_token']);
    expect(findings.find((f) => f.id === 'cookies.secure-missing')?.evidence).toEqual(['theme']);
  });
});

describe('blocksEverything', () => {
  it('detects a full block for all agents', () => {
    expect(blocksEverything('User-agent: *\nDisallow: /')).toBe(true);
  });
  it('honours an Allow tie and per-agent groups', () => {
    expect(blocksEverything('User-agent: *\nAllow: /\nDisallow: /')).toBe(false);
    expect(blocksEverything('User-agent: BadBot\nDisallow: /\n\nUser-agent: *\nDisallow: /admin')).toBe(false);
    expect(blocksEverything('User-agent: *\nUser-agent: Googlebot\nDisallow: /')).toBe(true);
    expect(blocksEverything('User-agent: Googlebot\nDisallow:\n\nUser-agent: *\nDisallow: / # staging')).toBe(true);
  });
});

describe('score', () => {
  const f = (severity: Finding['severity']): Finding => ({ id: 'x', category: 'headers', severity, title: '', detail: '', fix: '' });
  it('subtracts weights and caps critical sites', () => {
    expect(score([])).toBe(100);
    expect(score([f('medium'), f('low'), f('info')])).toBe(92);
    expect(score([f('critical')])).toBe(40);
    expect(score(Array.from({ length: 20 }, () => f('high')))).toBe(0);
  });
  it('grades', () => {
    expect([95, 85, 70, 55, 10].map(grade)).toEqual(['A', 'B', 'C', 'D', 'F']);
  });
});

describe('urls and scope', () => {
  it('normalizes bare domains and refuses other schemes', () => {
    expect(normalizeUrl(' example.com/path#x ')).toBe('https://example.com/path');
    expect(normalizeUrl('http://example.com')).toBe('http://example.com/');
    expect(() => normalizeUrl('ftp://example.com')).toThrow(/unsupported/);
  });

  it('groups subdomains but keeps shared hosting tenants apart', () => {
    expect(siteKey('cdn.shop.example.com')).toBe('example.com');
    expect(siteKey('www.example.co.uk')).toBe('example.co.uk');
    expect(siteKey('my-app.vercel.app')).toBe('my-app.vercel.app');
    expect(isFirstParty('https://static.example.com/a.js', 'https://www.example.com/')).toBe(true);
    expect(isFirstParty('https://other.vercel.app/a.js', 'https://mine.vercel.app/')).toBe(false);
  });

  it('extracts lazy chunk paths from bundles', () => {
    const js = 'm.f||(m.f=["assets/About-x1.js","assets/About-x1.css"]);import("./Chart-y2.js");e="/_next/static/chunks/9-abc.js"';
    expect(chunkReferences(js, 'https://a.example/assets/index.js')).toEqual([
      'https://a.example/assets/About-x1.js',
      'https://a.example/_next/static/chunks/9-abc.js',
    ]);
  });
});

describe('followRedirects', () => {
  it('records the chain and resolves relative locations', async () => {
    const routes: Record<string, HttpResponse> = {
      'http://a.example/': response('http://a.example/', 301, { location: 'https://a.example/' }),
      'https://a.example/': response('https://a.example/', 302, { location: '/home' }),
      'https://a.example/home': response('https://a.example/home', 200),
    };
    const result = await followRedirects((url) => Promise.resolve(routes[url] ?? response(url, 404)), 'http://a.example/');
    expect(result.chain.map((h) => h.status)).toEqual([301, 302]);
    expect(result.response.url).toBe('https://a.example/home');
  });

  it('stops redirect loops', async () => {
    const loop = (url: string): Promise<HttpResponse> => Promise.resolve(response(url, 302, { location: url }));
    await expect(followRedirects(loop, 'https://a.example/', 3)).rejects.toThrow(/redirects/);
  });
});

describe('checkSeo robots', () => {
  it('explains an SPA fallback instead of a robots file', () => {
    const findings = checkSeo(snapshot({ robots: { status: 200, text: '', htmlFallback: true } }));
    expect(findings.find((f) => f.id === 'seo.robots-missing')?.detail).toMatch(/HTML page/);
  });
});
