import type { AuditResult, Finding, LighthouseOpportunity, LighthouseSummary } from './types.js';

/**
 * Hooks: the few measured facts about a site that matter most to its owner, written as plain
 * sentences with numbers. They are meant to be read by a non-developer (or adapted into the first
 * line of a message), so they avoid metric acronyms and header names.
 */
export interface Hook {
  id: string;
  source: 'security' | 'performance' | 'seo' | 'accessibility';
  /** Higher = more important; only used for ranking. */
  weight: number;
  sentence: string;
  /**
   * Short work item for the fix scope line, e.g. "add the missing security headers". Null for a
   * symptom (a slow overall score) whose work is named by the more specific hooks.
   */
  scope: string | null;
  /** Rough effort for that work item, in hours. */
  hours: number;
}

export interface HookReport {
  hooks: Hook[];
  /** One line: what a fixed-price job would cover and roughly how long it takes. */
  scope: string | null;
  hours: number;
}

export const MAX_HOOKS = 3;
/** A Lighthouse saving smaller than this is true but too small to open a conversation with. */
const MIN_HOOK_SAVINGS_MS = 300;
const MIN_HOOK_SAVINGS_BYTES = 100 * 1024;

const seconds = (ms: number): string => `${(ms / 1000).toFixed(1)} s`;
const size = (kb: number): string => (kb >= 1000 ? `${(kb / 1024).toFixed(1)} MB` : `${Math.round(kb)} KB`);

/** Header checks grouped into one hook so three header findings don't crowd out everything else. */
const HEADER_IDS = new Set([
  'headers.csp-missing',
  'headers.clickjacking',
  'headers.nosniff-missing',
  'headers.referrer-policy-missing',
  'headers.permissions-policy-missing',
  'transport.hsts-missing',
]);

/** What a missing header leaves open, in words a site owner understands. */
const HEADER_GAPS: Partial<Record<string, string>> = {
  'headers.csp-missing': 'injected scripts',
  'headers.clickjacking': 'other sites framing the page',
  'transport.hsts-missing': 'a downgrade to plain http://',
};

/** The count a finding title carries in parentheses, e.g. "Source maps are public (12)". */
const countIn = (title: string): number | undefined => {
  const match = /\((\d+)\)/.exec(title)?.[1];
  return match ? Number(match) : undefined;
};

const joinOr = (items: string[]): string =>
  items.length <= 1 ? (items[0] ?? '') : `${items.slice(0, -1).join(', ')} or ${items.at(-1) ?? ''}`;

function secretHook(f: Finding): Hook {
  const what = f.title.replace(/\s+(exposed|found)\s+in\s+.*$/i, '');
  return {
    id: f.id,
    source: 'security',
    weight: 100,
    sentence: `${what} is visible in the site's public JavaScript, so anyone who opens the page can copy it.`,
    scope: 'rotate the leaked key and move it to a server function',
    hours: 3,
  };
}

export function securityHooks(findings: Finding[]): Hook[] {
  const hooks: Hook[] = [];
  const has = (id: string): Finding | undefined => findings.find((f) => f.id === id);

  for (const f of findings) {
    if (f.category === 'secrets' && (f.severity === 'critical' || f.severity === 'high')) hooks.push(secretHook(f));
  }

  const tls = has('transport.tls-invalid');
  if (tls) {
    hooks.push({
      id: tls.id,
      source: 'security',
      weight: 98,
      sentence: 'The HTTPS certificate is not valid, so browsers show visitors a full-page security warning.',
      scope: 'fix the HTTPS certificate',
      hours: 1,
    });
  }

  for (const id of ['exposure.env-file', 'exposure.git-dir'] as const) {
    const f = has(id);
    if (!f) continue;
    const path = id === 'exposure.env-file' ? '/.env' : '/.git';
    hooks.push({
      id,
      source: 'security',
      weight: 95,
      sentence: `Anyone can download the site's ${path} ${id === 'exposure.env-file' ? 'settings file' : 'folder'} straight from the browser.`,
      scope: `block public access to ${path} and rotate what it contained`,
      hours: 2,
    });
  }

  const noHttps = has('transport.no-https');
  if (noHttps) {
    hooks.push({
      id: noHttps.id,
      source: 'security',
      weight: 90,
      sentence: 'The site is served without HTTPS, so browsers mark it "Not secure" and anything typed into it travels unencrypted.',
      scope: 'move the site to HTTPS',
      hours: 2,
    });
  }

  const dev = has('exposure.dev-server');
  if (dev) {
    hooks.push({
      id: dev.id,
      source: 'security',
      weight: 85,
      sentence: 'The live site is running a development server, which is slower and exposes the source code.',
      scope: 'deploy a production build',
      hours: 2,
    });
  }

  const maps = has('exposure.source-maps');
  if (maps) {
    hooks.push({
      id: maps.id,
      source: 'security',
      weight: 45,
      sentence: `The original, readable source code behind the site's JavaScript can be downloaded through public source map files (${countIn(maps.title) ?? maps.evidence?.length ?? 1} found).`,
      scope: 'stop publishing source maps',
      hours: 1,
    });
  }

  const plainHttp = has('transport.no-http-redirect');
  if (plainHttp) {
    hooks.push({
      id: plainHttp.id,
      source: 'security',
      weight: 55,
      sentence: 'Typing the plain http:// address still opens the site without encryption instead of switching to https://.',
      scope: 'redirect http:// to https://',
      hours: 0.5,
    });
  }

  const missingHeaders = findings.filter((f) => HEADER_IDS.has(f.id));
  if (missingHeaders.length >= 2) {
    const sent = HEADER_IDS.size - missingHeaders.length;
    const gaps = missingHeaders.flatMap((f) => {
      const gap = HEADER_GAPS[f.id];
      return gap ? [gap] : [];
    });
    const so = gaps.length > 0 ? `, so nothing stops ${joinOr(gaps)}` : '';
    hooks.push({
      id: 'headers.group',
      source: 'security',
      weight: 30 + 4 * missingHeaders.length,
      sentence: `The server sends ${sent === 0 ? 'none' : `only ${sent}`} of the ${HEADER_IDS.size} standard security headers browsers look for${so}.`,
      scope: 'add the missing security headers',
      hours: 2,
    });
  }

  const cookie = has('cookies.httponly-missing') ?? has('cookies.secure-missing');
  if (cookie) {
    hooks.push({
      id: cookie.id,
      source: 'security',
      weight: 45,
      sentence:
        cookie.id === 'cookies.httponly-missing'
          ? 'The session cookie can be read by any script on the page, which makes a stolen login easier.'
          : 'The session cookie can be sent over plain http://, where it is not encrypted.',
      scope: 'tighten the cookie settings',
      hours: 1,
    });
  }

  return hooks;
}

interface OpportunityText {
  sentence: (o: { saving: string | null; kb: number; ms: number; lh: LighthouseSummary }) => string;
  scope: string;
  hours: number;
  weight?: number;
}

const imageText: OpportunityText = {
  sentence: ({ saving, kb, lh }) => {
    const lead = lh.totalKb !== null && lh.totalKb >= 2000 ? `This page weighs ${size(lh.totalKb)} on a phone, and its` : 'The';
    return `${lead} images could be about ${size(kb)} smaller with the right size and format${saving ? `, showing the page ${saving}` : ''}.`;
  },
  scope: 'resize and convert the images',
  hours: 2,
};

/** Plain-language versions of the Lighthouse opportunities that come up most often. */
const OPPORTUNITY_TEXT: Partial<Record<string, OpportunityText>> = {
  'render-blocking-insight': {
    sentence: ({ saving }) =>
      `A few CSS, font or script files hold back the first paint; loading them differently would show the page ${saving ?? 'sooner'} on a phone.`,
    scope: 'unblock the first paint (critical CSS, font loading)',
    hours: 3,
  },
  'image-delivery-insight': imageText,
  'uses-responsive-images': imageText,
  'modern-image-formats': imageText,
  'unused-javascript': {
    sentence: ({ kb }) => `About ${size(kb)} of the JavaScript downloaded on this page is never used here.`,
    scope: 'split and trim the JavaScript bundles',
    hours: 4,
  },
  'unused-css-rules': {
    sentence: ({ kb, saving }) => `About ${size(kb)} of the CSS is not used on this page${saving ? `; removing it would show the page ${saving}` : ''}.`,
    scope: 'remove unused CSS',
    hours: 2,
  },
  'document-latency-insight': {
    sentence: ({ saving }) => `The server is slow to send the page itself${saving ? `; fixing that would show it ${saving}` : ''}.`,
    scope: 'speed up the server response (caching)',
    hours: 3,
  },
  'third-parties-insight': {
    sentence: ({ saving, ms }) => `Third-party scripts (chat, analytics, embeds) slow the first view down${saving ? ` by about ${seconds(ms)}` : ''}.`,
    scope: 'delay third-party scripts until after load',
    hours: 2,
  },
  'font-display-insight': {
    sentence: ({ saving, ms }) => `Text stays invisible while web fonts load${saving ? `, for up to ${seconds(ms)}` : ''}.`,
    scope: 'fix font loading',
    hours: 1,
  },
  'legacy-javascript-insight': {
    sentence: ({ kb }) => `The site ships about ${size(kb)} of old-browser JavaScript that modern phones don't need.`,
    scope: 'drop legacy JavaScript polyfills',
    hours: 2,
  },
  'cache-insight': {
    sentence: ({ kb }) => `Repeat visitors re-download about ${size(kb)} because files are cached for too short a time.`,
    scope: 'set long cache lifetimes for static files',
    hours: 1,
    weight: 25,
  },
  'lcp-discovery-insight': {
    sentence: ({ saving }) => `The browser finds the main image late${saving ? `; loading it first would show it ${saving}` : ''}.`,
    scope: 'preload the main image',
    hours: 1,
  },
};

function opportunityHook(o: LighthouseOpportunity, lh: LighthouseSummary): Hook | null {
  const text = OPPORTUNITY_TEXT[o.id];
  if (!text || (o.savingsMs < MIN_HOOK_SAVINGS_MS && o.savingsBytes < MIN_HOOK_SAVINGS_BYTES)) return null;
  const saving = o.savingsMs >= 100 ? `about ${seconds(o.savingsMs)} sooner` : null;
  return {
    id: `lighthouse.${o.id}`,
    source: 'performance',
    weight: text.weight ?? 30 + Math.min(40, o.savingsMs / 50),
    sentence: text.sentence({ saving, kb: Math.round(o.savingsBytes / 1024), ms: o.savingsMs, lh }),
    scope: text.scope,
    hours: text.hours,
  };
}

export function performanceHooks(lh: LighthouseSummary): Hook[] {
  const hooks: Hook[] = [];
  const perf = lh.scores.performance;

  if (lh.lcpMs !== null && (lh.lcpMs > 2500 || (perf !== null && perf < 90))) {
    const scorePart = perf !== null ? `Google Lighthouse rates the page ${perf}/100 for speed on a phone` : 'On a mid-range phone';
    const slow = lh.lcpMs > 2500;
    hooks.push({
      id: 'lighthouse.speed',
      source: 'performance',
      weight: 40 + Math.min(50, Math.max(0, (lh.lcpMs - 2500) / 100)) + (perf !== null ? (90 - perf) / 3 : 0),
      sentence: `${scorePart}: the main content appears after ${seconds(lh.lcpMs)}${slow ? ' (Google counts under 2.5 s as good)' : ''}.`,
      scope: null,
      hours: 0,
    });
  }

  if (lh.tbtMs !== null && lh.tbtMs > 600) {
    hooks.push({
      id: 'lighthouse.frozen',
      source: 'performance',
      weight: 35 + Math.min(40, lh.tbtMs / 100),
      sentence: `While it loads, the page is frozen for about ${seconds(lh.tbtMs)} in total, so taps and scrolls do nothing.`,
      scope: 'cut the JavaScript work on load',
      hours: 4,
    });
  }

  if (lh.cls !== null && lh.cls > 0.1) {
    hooks.push({
      id: 'lighthouse.layout-shift',
      source: 'performance',
      weight: 40 + Math.min(30, lh.cls * 60),
      sentence: `Content jumps around while the page loads (layout shift ${lh.cls.toFixed(2)}, Google's limit for good is 0.1), which causes mis-taps.`,
      scope: 'stop the layout jumps',
      hours: 2,
    });
  }

  if (lh.jsKb !== null && lh.jsKb > 500) {
    hooks.push({
      id: 'lighthouse.js-weight',
      source: 'performance',
      weight: 30 + Math.min(30, (lh.jsKb - 500) / 50),
      sentence: `A phone has to download ${size(lh.jsKb)} of JavaScript (${lh.jsRequests ?? '?'} files, compressed) to show this page.`,
      scope: 'split and trim the JavaScript bundles',
      hours: 4,
    });
  }

  for (const o of lh.opportunities) {
    const hook = opportunityHook(o, lh);
    if (hook) hooks.push(hook);
  }

  const { accessibility, seo } = lh.scores;
  if (accessibility !== null && accessibility < 80) {
    hooks.push({
      id: 'lighthouse.accessibility',
      source: 'accessibility',
      weight: 30 + (80 - accessibility) / 2,
      sentence: `Lighthouse gives the page ${accessibility}/100 for accessibility (things like missing labels or low-contrast text).`,
      scope: 'fix the accessibility issues Lighthouse lists',
      hours: 3,
    });
  }
  if (seo !== null && seo < 80) {
    hooks.push({
      id: 'lighthouse.seo',
      source: 'seo',
      weight: 30 + (80 - seo) / 2,
      sentence: `Lighthouse gives the page ${seo}/100 for search-engine basics.`,
      scope: 'fix the SEO basics',
      hours: 2,
    });
  }

  return hooks;
}

/** Keeps one hook per work item: two hooks that lead to the same fix would waste a slot. */
function dedupeByScope(hooks: Hook[]): Hook[] {
  const seen = new Set<string>();
  return hooks.filter((h) => {
    if (h.scope === null) return true;
    if (seen.has(h.scope)) return false;
    seen.add(h.scope);
    return true;
  });
}

/**
 * Picks the strongest hooks. When both security and speed have something to say, the top three
 * always include at least one of each, since that pairing is what a single audit is good for.
 */
export function pickHooks(candidates: Hook[], limit = MAX_HOOKS): Hook[] {
  const ranked = dedupeByScope([...candidates].sort((a, b) => b.weight - a.weight));
  const top = ranked.slice(0, limit);
  const isSecurity = (h: Hook): boolean => h.source === 'security';
  if (top.length === limit) {
    const swap = top.every(isSecurity)
      ? ranked.find((h) => !isSecurity(h))
      : top.some(isSecurity)
        ? undefined
        : ranked.find(isSecurity);
    if (swap) top[limit - 1] = swap;
  }
  return top;
}

const formatHours = (h: number): string => (h <= 1 ? 'about 1 hour' : `about ${Math.ceil(h)} hours`);

/** Used when the page is slow but no specific Lighthouse opportunity explains it. */
const GENERIC_SPEED_WORK: Hook = {
  id: 'lighthouse.generic',
  source: 'performance',
  weight: 0,
  sentence: '',
  scope: 'find and fix what slows the mobile page load',
  hours: 4,
};

/**
 * The work items behind the picked hooks. A picked symptom (slow speed score) with no concrete
 * speed item next to it borrows the strongest one from the candidates that did not make the cut.
 */
export function workItems(picked: Hook[], candidates: Hook[]): Hook[] {
  const work = picked.filter((h) => h.scope !== null);
  const symptom = picked.some((h) => h.scope === null);
  if (symptom && !work.some((h) => h.source === 'performance')) {
    const best = [...candidates]
      .sort((a, b) => b.weight - a.weight)
      .find((h) => h.source === 'performance' && h.scope !== null && !work.some((w) => w.scope === h.scope));
    work.push(best ?? GENERIC_SPEED_WORK);
  }
  return work;
}

export function scopeLine(work: Hook[], hourlyRate?: number): string | null {
  const items = work.flatMap((h) => (h.scope === null ? [] : [h.scope]));
  if (items.length === 0) return null;
  const list = items.length === 1 ? (items[0] as string) : `${items.slice(0, -1).join(', ')} and ${items.at(-1) as string}`;
  const hours = work.reduce((sum, h) => sum + h.hours, 0);
  const price = hourlyRate ? `, $${Math.ceil((hours * hourlyRate) / 10) * 10} fixed` : '';
  return `Fixed-price scope: ${list}; ${formatHours(hours)} of work${price}, with a before/after re-run of this audit.`;
}

export function buildHooks(result: AuditResult, options: { hourlyRate?: number } = {}): HookReport {
  const lh = result.lighthouse && !('error' in result.lighthouse) ? result.lighthouse : undefined;
  const candidates = [...securityHooks(result.findings), ...(lh ? performanceHooks(lh) : [])];
  const hooks = pickHooks(candidates);
  const work = workItems(hooks, candidates);
  return { hooks, scope: scopeLine(work, options.hourlyRate), hours: work.reduce((sum, h) => sum + h.hours, 0) };
}
