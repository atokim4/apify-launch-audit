import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { gzipSync } from 'node:zlib';
import { FAKE, PEM_HEADER } from './keys.js';

export interface Route {
  status?: number;
  type?: string;
  body: string;
  headers?: Record<string, string | string[]>;
}

const SPA_FALLBACK: Route = { type: 'text/html', body: '<!doctype html><html><body>app</body></html>' };

/** A careless Vite + Supabase app: leaked keys, no headers, public source map and .env. */
export function leakyRoutes(): Record<string, Route> {
  return {
    '/': {
      type: 'text/html',
      headers: { 'set-cookie': ['session_id=abc; Path=/', 'theme=dark; Path=/; SameSite=Lax'], 'x-powered-by': 'Express 4.18.2' },
      body: `<!doctype html><html><head><title>Demo shop</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<script type="module" crossorigin src="/assets/index-Ab12Cd34.js"></script>
<script src="https://cdn.thirdparty.example/widget.js"></script>
<script>window.__CONFIG__ = { supabaseUrl: "${FAKE.supabaseUrl}" }</script>
</head><body><div id="root"></div></body></html>`,
    },
    '/assets/index-Ab12Cd34.js': {
      type: 'application/javascript',
      body: `const s="${FAKE.stripeLive}";const k="${FAKE.anon}";
const __vitePreload=["assets/admin-Ef56Gh78.js"];console.log("react.dev/errors");
//# sourceMappingURL=index-Ab12Cd34.js.map`,
    },
    '/assets/index-Ab12Cd34.js.map': {
      type: 'application/json',
      body: '{"version":3,"sources":["../src/main.tsx"],"mappings":"AAAA"}',
    },
    '/assets/admin-Ef56Gh78.js': {
      type: 'application/javascript',
      body: `export const admin="${FAKE.serviceRole}";const ai="${FAKE.openai}";const c="${FAKE.anthropic}";const pem="${FAKE.privateKey}";const r="${FAKE.stripeRestricted}";`,
    },
    '/robots.txt': { type: 'text/plain', body: 'User-agent: *\nDisallow: /\n' },
    '/.env': { type: 'text/plain', body: 'DATABASE_URL=postgres://fake\n' },
  };
}

/** A tidy site that still contains strings a naive scanner would flag. */
export function cleanRoutes(): Record<string, Route> {
  const headers = {
    'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'strict-origin-when-cross-origin',
    'permissions-policy': 'camera=()',
    'set-cookie': '__Host-sid=1; Path=/; Secure; HttpOnly; SameSite=Lax',
  };
  // Real-world noise: PEM parsing code, Stripe docs placeholders, publishable keys, non-Supabase JWTs.
  const library = [
    `const PEM="${PEM_HEADER}";`,
    `const docs="${FAKE.stripePlaceholder}";`,
    `const pk="${['pk', 'live', 'Zq9'.repeat(10)].join('_')}";`,
    `const prefix="sk-";const sample="${FAKE.genericJwt}";`,
    `const fb={apiKey:"${FAKE.firebaseApiKey}",authDomain:"demo-app-123.firebaseapp.com"};`,
    `/* ${'padding '.repeat(3000)} */`,
  ].join('\n');
  return {
    '/': {
      type: 'text/html',
      headers,
      body: `<!doctype html><html><head><title>Clean</title><meta name="description" content="A clean test page">
<meta name="viewport" content="width=device-width"><script src="/static/app.js"></script></head><body>ok</body></html>`,
    },
    '/static/app.js': { type: 'application/javascript', headers, body: `${library}\n//# sourceMappingURL=http://[bad` },
    '/robots.txt': { type: 'text/plain', body: 'User-agent: *\nAllow: /\nSitemap: /sitemap.xml\n' },
    '/sitemap.xml': { type: 'application/xml', body: '<?xml version="1.0"?><urlset></urlset>' },
    // SPA-style fallbacks that must not be mistaken for leaks:
    '/.env': SPA_FALLBACK,
    '/.git/HEAD': SPA_FALLBACK,
    '/static/app.js.map': SPA_FALLBACK,
  };
}

export interface FixtureServer {
  url: string;
  close: () => Promise<void>;
}

export async function startFixture(routes: Record<string, Route>, { gzip = false } = {}): Promise<FixtureServer> {
  const server: Server = createServer((req, res) => {
    const path = new URL(req.url ?? '/', 'http://localhost').pathname;
    const route = routes[path];
    if (!route) {
      res.writeHead(404, { 'content-type': 'text/plain' }).end('not found');
      return;
    }
    const headers: Record<string, string | string[]> = { 'content-type': route.type ?? 'text/plain', ...route.headers };
    let payload: Buffer = Buffer.from(route.body);
    if (gzip && /gzip/.test(String(req.headers['accept-encoding']))) {
      payload = gzipSync(payload);
      headers['content-encoding'] = 'gzip';
    }
    res.writeHead(route.status ?? 200, headers).end(payload);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}/`,
    close: () =>
      new Promise((resolve, reject) => {
        server.close((err) => {
          if (err) reject(err);
          else resolve();
        });
      }),
  };
}
