import * as cheerio from 'cheerio';
import type { PageInfo } from './snapshot.js';

export function parsePage(html: string, pageUrl: string): PageInfo {
  const $ = cheerio.load(html);
  const resolve = (value: string | undefined): string | null => {
    if (!value) return null;
    try {
      return new URL(value, pageUrl).toString();
    } catch {
      return null;
    }
  };

  const scripts = new Set<string>();
  $('script[src]').each((_, el) => {
    const url = resolve($(el).attr('src'));
    if (url) scripts.add(url);
  });
  $('link[rel="modulepreload"], link[rel="preload"][as="script"]').each((_, el) => {
    const url = resolve($(el).attr('href'));
    if (url) scripts.add(url);
  });

  const stylesheets = $('link[rel="stylesheet"]')
    .map((_, el) => resolve($(el).attr('href')))
    .get()
    .filter((u): u is string => !!u);

  const insecureResources: string[] = [];
  if (pageUrl.startsWith('https://')) {
    $('script[src], link[rel="stylesheet"][href], img[src], iframe[src]').each((_, el) => {
      const raw = $(el).attr('src') ?? $(el).attr('href') ?? '';
      if (raw.startsWith('http://')) insecureResources.push(raw);
    });
  }

  const meta = (name: string): string | null => $(`meta[name="${name}" i]`).attr('content')?.trim() || null;

  return {
    title: $('title').first().text().trim() || null,
    description: meta('description'),
    viewport: meta('viewport') !== null,
    metaRobots: meta('robots'),
    generator: meta('generator'),
    scripts: [...scripts],
    stylesheets,
    images: $('img').length,
    insecureResources,
    html,
  };
}

/** Chunk paths referenced inside a JS bundle (Vite, Next.js, Nuxt, SvelteKit, Astro). */
export function chunkReferences(js: string, bundleUrl: string): string[] {
  const out = new Set<string>();
  const re = /["'`]((?:\/|\.\/|\.\.\/)?(?:[\w.-]+\/)*(?:assets|_next\/static|_nuxt|_app\/immutable|_astro|_vercel\/immutable)\/[\w./-]+\.m?js)["'`]/g;
  for (const m of js.matchAll(re)) {
    const path = m[1];
    if (!path) continue;
    try {
      // Bare "assets/x.js" from Vite's preload list is relative to the site root.
      const base = path.startsWith('.') ? bundleUrl : new URL('/', bundleUrl).toString();
      out.add(new URL(path, base).toString());
    } catch {
      // ignore malformed references
    }
  }
  return [...out];
}

/** Public-suffix-like hosting domains where every customer gets a subdomain. */
const SHARED_HOSTS = [
  'vercel.app', 'netlify.app', 'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com', 'github.io',
  'herokuapp.com', 'onrender.com', 'fly.dev', 'lovable.app', 'replit.app', 'surge.sh', 'azurewebsites.net',
];

export function siteKey(hostname: string): string {
  const host = hostname.toLowerCase();
  if (SHARED_HOSTS.some((d) => host === d || host.endsWith(`.${d}`))) return host;
  if (/^[\d.]+$/.test(host) || host.includes(':') || !host.includes('.')) return host;
  const labels = host.split('.');
  const secondLevel = labels.at(-2) ?? '';
  const take = labels.length > 2 && secondLevel.length <= 3 && (labels.at(-1)?.length ?? 0) === 2 ? 3 : 2;
  return labels.slice(-take).join('.');
}

/** Scripts served by the site itself (same registrable domain), not third-party tags. */
export function isFirstParty(url: string, pageUrl: string): boolean {
  return siteKey(new URL(url).hostname) === siteKey(new URL(pageUrl).hostname);
}
