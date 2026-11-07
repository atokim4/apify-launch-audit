import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { auditSite } from '../src/audit.js';
import { type Fetcher, FetchError } from '../src/http.js';
import { toMarkdownReport } from '../src/report.js';
import type { AuditResult } from '../src/types.js';
import { FAKE } from './fixtures/keys.js';
import { cleanRoutes, type FixtureServer, leakyRoutes, startFixture } from './fixtures/server.js';

const ids = (r: AuditResult): string[] => r.findings.map((f) => f.id);

describe('auditSite on a leaky Vite + Supabase app', () => {
  let server: FixtureServer;
  let result: AuditResult;

  beforeAll(async () => {
    server = await startFixture(leakyRoutes());
    result = await auditSite(server.url, { timeoutMs: 5000, allowPrivateNetwork: true });
  });
  afterAll(() => server.close());

  it('finds every planted secret, including ones in lazily loaded chunks', () => {
    expect(ids(result)).toEqual(
      expect.arrayContaining([
        'secrets.stripe-live-secret',
        'secrets.stripe-live-restricted',
        'secrets.supabase-service-role',
        'secrets.openai-key',
        'secrets.anthropic-key',
        'secrets.private-key',
      ]),
    );
    expect(result.metrics.scriptsScanned).toBe(2);
  });

  it('never prints a full secret', () => {
    const output = JSON.stringify(result) + toMarkdownReport([result]);
    for (const value of [FAKE.stripeLive, FAKE.stripeRestricted, FAKE.openai, FAKE.anthropic, FAKE.serviceRole]) {
      expect(output).not.toContain(value);
      expect(output).not.toContain(value.slice(0, 30));
    }
  });

  it('reports Supabase config, source maps, .env and the robots block', () => {
    expect(ids(result)).toEqual(
      expect.arrayContaining(['backend.supabase-verify-rls', 'exposure.source-maps', 'exposure.env-file', 'seo.robots-blocks-all']),
    );
    expect(ids(result)).not.toContain('exposure.git-dir');
  });

  it('flags missing headers, cookie flags and version disclosure', () => {
    expect(ids(result)).toEqual(
      expect.arrayContaining(['transport.no-https', 'headers.csp-missing', 'headers.clickjacking', 'cookies.httponly-missing', 'headers.version-disclosure']),
    );
    const cookie = result.findings.find((f) => f.id === 'cookies.httponly-missing');
    expect(cookie?.evidence).toEqual(['session_id']);
  });

  it('ignores third-party scripts and detects the stack', () => {
    expect(JSON.stringify(result)).not.toContain('cdn.thirdparty.example/widget.js.map');
    expect(result.stack.frameworks).toEqual(expect.arrayContaining(['Vite', 'React']));
  });

  it('caps the score when something is critical', () => {
    expect(result.score).toBeLessThanOrEqual(40);
    expect(result.grade).toBe('F');
    expect(result.findings[0]?.severity).toBe('critical');
  });
});

describe('auditSite on a clean site', () => {
  let server: FixtureServer;
  let result: AuditResult;

  beforeAll(async () => {
    server = await startFixture(cleanRoutes(), { gzip: true });
    result = await auditSite(server.url, { timeoutMs: 5000, allowPrivateNetwork: true });
  });
  afterAll(() => server.close());

  it('has no false positives from library strings, placeholders or SPA fallbacks', () => {
    // Plain http is the only real problem with the fixture (it cannot have a certificate).
    // Firebase web config is public by design and only produces a "verify rules" note.
    expect(ids(result).sort()).toEqual(['backend.firebase-verify-rules', 'transport.no-https']);
    expect(result.findings.find((f) => f.id === 'backend.firebase-verify-rules')?.evidence).toEqual(['project: demo-app-123']);
  });

  it('decompresses gzip and measures transfer size', () => {
    expect(result.metrics.jsBytes).toBeGreaterThan(20_000);
    expect(result.metrics.htmlTransferBytes).toBeLessThan(result.metrics.htmlBytes);
  });
});

describe('auditSite error handling', () => {
  it('returns an error result instead of throwing for an unreachable host', async () => {
    const server = await startFixture({});
    const url = server.url;
    await server.close();
    const result = await auditSite(url, { timeoutMs: 2000, allowPrivateNetwork: true });
    expect(result.error).toMatch(/ECONNREFUSED/);
    expect(result.score).toBe(0);
    expect(toMarkdownReport([result])).toContain('Could not audit this URL');
  });

  it('rejects non-http protocols', async () => {
    const result = await auditSite('file:///etc/passwd');
    expect(result.error).toMatch(/unsupported protocol/);
  });
});

describe('private network guard', () => {
  it('refuses localhost and private IPs unless allowed', async () => {
    const server = await startFixture(cleanRoutes());
    try {
      const blocked = await auditSite(server.url, { timeoutMs: 2000 });
      expect(blocked.error).toMatch(/private or local address/);
      const viaName = await auditSite(server.url.replace('127.0.0.1', 'localhost'), { timeoutMs: 2000 });
      expect(viaName.error).toMatch(/private or local address/);
      for (const host of ['http://169.254.169.254/', 'http://10.1.2.3/', 'http://[::1]/']) {
        expect((await auditSite(host, { timeoutMs: 2000 })).error).toMatch(/private or local address/);
      }
    } finally {
      await server.close();
    }
  });
});

describe('dev server and .git exposure', () => {
  it('flags a Vite dev server and a served .git directory', async () => {
    const server = await startFixture({
      '/': { type: 'text/html', body: '<!doctype html><html><head><script type="module" src="/@vite/client"></script></head></html>' },
      '/.git/HEAD': { type: 'text/plain', body: 'ref: refs/heads/main\n' },
    });
    try {
      const result = await auditSite(server.url, { allowPrivateNetwork: true });
      expect(result.findings.map((f) => f.id)).toEqual(expect.arrayContaining(['exposure.dev-server', 'exposure.git-dir']));
    } finally {
      await server.close();
    }
  });
});

describe('invalid certificate', () => {
  it('reports the TLS error and still audits the http version', async () => {
    const fetcher: Fetcher = (url) => {
      if (url.startsWith('https://')) return Promise.reject(new FetchError('certificate has expired', url, 'CERT_HAS_EXPIRED'));
      return Promise.resolve({
        url,
        status: 200,
        headers: { 'content-type': 'text/html' },
        setCookies: [],
        body: Buffer.from('<html><title>t</title></html>'),
        transferBytes: 30,
        ttfbMs: 5,
        truncated: false,
      });
    };
    const result = await auditSite('https://expired.example/', {}, fetcher);
    expect(result.error).toBeUndefined();
    expect(result.findings[0]?.id).toBe('transport.tls-invalid');
    expect(result.finalUrl).toBe('http://expired.example/');
  });
});

describe('certificate broken on every path', () => {
  it('returns the TLS finding together with the error', async () => {
    const fetcher: Fetcher = (url) => Promise.reject(new FetchError('certificate has expired', url, 'CERT_HAS_EXPIRED'));
    const result = await auditSite('expired.example', {}, fetcher);
    expect(result.error).toMatch(/certificate/);
    expect(result.findings.map((f) => f.id)).toEqual(['transport.tls-invalid']);
    expect(toMarkdownReport([result])).toContain('HTTPS certificate is not valid');
  });
});
