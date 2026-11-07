import type { SiteSnapshot } from '../snapshot.js';
import type { Finding } from '../types.js';

/**
 * True when robots.txt blocks the whole site for all crawlers: the `User-agent: *` group
 * disallows `/` and has no Allow rule for the root (RFC 9309: Allow wins on a tie).
 */
export function blocksEverything(robots: string): boolean {
  let groupAgents: string[] = [];
  let inRules = false;
  let disallowRoot = false;
  let allowRoot = false;
  for (const raw of robots.split(/\r?\n/)) {
    const line = raw.replace(/#.*/, '').trim();
    const colon = line.indexOf(':');
    if (colon < 0) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (key === 'user-agent') {
      if (inRules) {
        groupAgents = [];
        inRules = false;
      }
      groupAgents.push(value);
      continue;
    }
    if (key !== 'allow' && key !== 'disallow') continue;
    inRules = true;
    if (!groupAgents.includes('*')) continue;
    if (key === 'disallow' && value === '/') disallowRoot = true;
    if (key === 'allow' && (value === '/' || value === '/$')) allowRoot = true;
  }
  return disallowRoot && !allowRoot;
}

export function checkSeo(s: SiteSnapshot): Finding[] {
  const findings: Finding[] = [];
  const robots = s.robots;

  if (!robots || robots.status !== 200 || robots.htmlFallback) {
    const answer = !robots ? 'no response' : robots.htmlFallback ? 'an HTML page (app fallback)' : `status ${robots.status}`;
    findings.push({
      id: 'seo.robots-missing',
      category: 'seo',
      severity: 'low',
      title: 'No robots.txt',
      detail: `${new URL('/robots.txt', s.finalUrl).toString()} returned ${answer}.`,
      fix: 'Add a robots.txt that allows crawling and points to the sitemap (`Sitemap: https://…/sitemap.xml`).',
    });
  } else if (blocksEverything(robots.text)) {
    findings.push({
      id: 'seo.robots-blocks-all',
      category: 'seo',
      severity: 'medium',
      title: 'robots.txt blocks all crawlers',
      detail: '`User-agent: *` + `Disallow: /` keeps the site out of search results. Fine for staging, wrong for launch.',
      fix: 'Remove `Disallow: /` before launch.',
    });
  }

  if (s.sitemap && !s.sitemap.found) {
    findings.push({
      id: 'seo.sitemap-missing',
      category: 'seo',
      severity: 'low',
      title: 'No sitemap found',
      detail: `Checked ${s.sitemap.url}.`,
      fix: 'Generate a sitemap.xml (next-sitemap, @nuxtjs/sitemap, vite-plugin-sitemap) and list it in robots.txt.',
    });
  }

  const page = s.page;
  if (page) {
    if (page.metaRobots && /noindex/i.test(page.metaRobots)) {
      findings.push({
        id: 'seo.noindex',
        category: 'seo',
        severity: 'medium',
        title: 'Page is marked noindex',
        detail: `<meta name="robots" content="${page.metaRobots}">`,
        fix: 'Remove noindex from production pages.',
      });
    }
    if (!page.title) {
      findings.push({
        id: 'seo.title-missing',
        category: 'seo',
        severity: 'low',
        title: 'Missing <title>',
        detail: 'Search results and browser tabs show the URL instead of a name.',
        fix: 'Add a descriptive <title> (50-60 characters).',
      });
    }
    if (!page.description) {
      findings.push({
        id: 'seo.description-missing',
        category: 'seo',
        severity: 'low',
        title: 'Missing meta description',
        detail: 'Search engines will pick a random text snippet.',
        fix: 'Add `<meta name="description" content="…">` (120-160 characters).',
      });
    }
    if (!page.viewport) {
      findings.push({
        id: 'seo.viewport-missing',
        category: 'seo',
        severity: 'low',
        title: 'Missing viewport meta tag',
        detail: 'Phones render the page zoomed out at desktop width.',
        fix: 'Add `<meta name="viewport" content="width=device-width, initial-scale=1">`.',
      });
    }
  }
  return findings;
}
