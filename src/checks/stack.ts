import type { SiteSnapshot } from '../snapshot.js';
import type { Finding, Stack } from '../types.js';

interface Rule {
  name: string;
  html?: RegExp;
  header?: (h: Record<string, string>) => boolean;
  bundle?: RegExp;
}

const FRAMEWORKS: Rule[] = [
  { name: 'Next.js', html: /\/_next\/static\/|__NEXT_DATA__|self\.__next_f/, header: (h) => /next\.js/i.test(h['x-powered-by'] ?? '') || 'x-nextjs-cache' in h || 'x-nextjs-prerender' in h },
  { name: 'Nuxt', html: /\/_nuxt\/|window\.__NUXT__|id="__nuxt"/ },
  { name: 'Remix', html: /__remixContext|__remixManifest/ },
  { name: 'SvelteKit', html: /__sveltekit|\/_app\/immutable\// },
  { name: 'Astro', html: /<astro-island|\/_astro\// },
  { name: 'Gatsby', html: /id="___gatsby"/ },
  { name: 'Angular', html: /\sng-version="/ },
  { name: 'Vite', html: /<script[^>]+type="module"[^>]+src="[^"]*\/assets\/[^"]+-[\w-]{8}\.js"|\/@vite\/client/ },
  { name: 'React', html: /data-reactroot|id="__next"/, bundle: /react\.dev\/errors|reactjs\.org\/docs\/error-decoder|__REACT_DEVTOOLS_GLOBAL_HOOK__/ },
  { name: 'Vue', html: /\sdata-v-[0-9a-f]{8}|data-server-rendered/, bundle: /__VUE__|__vue_app__|__VUE_OPTIONS_API__/ },
  { name: 'Svelte', bundle: /svelte-[a-z0-9]{6}|__svelte/ },
  { name: 'WordPress', html: /\/wp-content\/|\/wp-includes\/|<meta name="generator" content="WordPress/i },
  { name: 'Shopify', html: /cdn\.shopify\.com|Shopify\.theme/, header: (h) => 'x-shopid' in h || 'x-shopify-stage' in h },
  { name: 'Wix', html: /static\.wixstatic\.com|<meta name="generator" content="Wix/i },
  { name: 'Webflow', html: /data-wf-page=|<meta content="Webflow" name="generator"/i },
];

const HOSTS: { name: string; test: (h: Record<string, string>) => boolean }[] = [
  { name: 'Vercel', test: (h) => 'x-vercel-id' in h || /vercel/i.test(h.server ?? '') },
  { name: 'Netlify', test: (h) => 'x-nf-request-id' in h || /netlify/i.test(h.server ?? '') },
  { name: 'Cloudflare', test: (h) => 'cf-ray' in h || /cloudflare/i.test(h.server ?? '') },
  { name: 'GitHub Pages', test: (h) => /github\.com/i.test(h.server ?? '') },
  { name: 'AWS CloudFront', test: (h) => 'x-amz-cf-id' in h },
  { name: 'AWS S3', test: (h) => /amazons3/i.test(h.server ?? '') },
  { name: 'Fly.io', test: (h) => 'fly-request-id' in h },
  { name: 'Render', test: (h) => 'rndr-id' in h || 'x-render-origin-server' in h },
  { name: 'Heroku', test: (h) => /vegur|heroku/i.test(h.via ?? '') },
  { name: 'Google Cloud', test: (h) => /google frontend/i.test(h.server ?? '') },
  { name: 'Azure', test: (h) => 'x-azure-ref' in h || 'x-ms-request-id' in h },
  { name: 'Fastly', test: (h) => /fastly/i.test(h['x-served-by'] ?? '') || 'x-fastly-request-id' in h },
  { name: 'Firebase Hosting', test: (h) => /firebase/i.test(h['x-powered-by'] ?? '') },
  { name: 'nginx', test: (h) => /^nginx/i.test(h.server ?? '') },
  { name: 'Apache', test: (h) => /^apache/i.test(h.server ?? '') },
];

/** Framework names whose runtime markers appear in one JS file. */
export function bundleHints(js: string): string[] {
  return FRAMEWORKS.filter((r) => r.bundle?.test(js) ?? false).map((r) => r.name);
}

export function detectStack(s: SiteSnapshot): Stack {
  const h = s.response.headers;
  const html = s.page?.html ?? '';
  const fromBundles = new Set(s.bundles.flatMap((b) => b.frameworkHints));
  const frameworks = FRAMEWORKS.filter(
    (r) => (r.html?.test(html) ?? false) || (r.header?.(h) ?? false) || fromBundles.has(r.name),
  ).map((r) => r.name);
  const hosting = HOSTS.filter((r) => r.test(h)).map((r) => r.name);
  return { frameworks, hosting };
}

export function checkStack(s: SiteSnapshot): Finding[] {
  if (!/\/@vite\/client|\/@react-refresh/.test(s.page?.html ?? '')) return [];
  return [
    {
      id: 'exposure.dev-server',
      category: 'exposure',
      severity: 'high',
      title: 'A development server is serving this site',
      detail: 'The page loads /@vite/client, so it runs `vite dev`: unminified code, source files under /src and no production hardening.',
      fix: 'Run `vite build` and serve the dist/ folder (or `vite preview` behind a real host) instead of the dev server.',
    },
  ];
}
