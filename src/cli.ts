#!/usr/bin/env node
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { auditSite, DEFAULTS, normalizeUrl } from './audit.js';
import { buildHooks } from './hooks.js';
import type { LighthouseOptions } from './lighthouse/run.js';
import { toHooksMarkdown, toMarkdownReport } from './report.js';
import { SEVERITY_ORDER } from './score.js';
import type { AuditResult, Severity } from './types.js';

const USAGE = `Usage: launch-audit <url> [url…] [options]

Passive pre-launch audit: HTTPS, security headers, cookies, leaked keys in JS bundles,
public source maps, exposed .env/.git, robots/sitemap, stack and page weight.

Options:
  --json               print JSON instead of Markdown
  --out <file>         also write the report to a file
  --max-bundles <n>    JS files to scan per site (default ${DEFAULTS.maxBundles})
  --timeout <ms>       per-request timeout (default ${DEFAULTS.timeoutMs})
  --fail-on <level>    exit 2 if a finding at this severity or worse exists
                       (critical | high | medium | low)

Lighthouse (needs Google Chrome or Chromium):
  --lighthouse         also run Lighthouse (mobile preset): performance, accessibility,
                       best-practices and SEO scores, LCP/CLS/TBT, JS weight, top savings
  --hooks              print only the 3 strongest findings across security and speed as plain
                       sentences, plus a one-line fix scope (implies --lighthouse)
  --rate <usd>         hourly rate used to price the fix scope line (optional)
  --lighthouse-timeout <s>  give up on Lighthouse after this many seconds (default 60)
  --chrome-path <path> Chrome binary (default: $CHROME_PATH, then auto-detect)
  --lighthouse-json <dir>   save each full Lighthouse report as <dir>/<host>.json

  -h, --help           show this help`;

function positiveInt(value: string | undefined, name: string, fallback: number): number {
  if (value === undefined) return fallback;
  const n = Number(value);
  if (!Number.isInteger(n) || n <= 0) throw new Error(`--${name} must be a positive integer`);
  return n;
}

function failsOn(results: AuditResult[], level: Severity): boolean {
  const worst = SEVERITY_ORDER.slice(0, SEVERITY_ORDER.indexOf(level) + 1);
  return results.some((r) => r.error !== undefined || worst.some((s) => r.counts[s] > 0));
}

/** File-safe name for a site's saved Lighthouse report, e.g. `shop.example.com`. */
function reportName(input: string): string {
  try {
    const url = new URL(normalizeUrl(input));
    return `${url.hostname}${url.pathname === '/' ? '' : url.pathname}`.replace(/[^a-z0-9.-]+/gi, '_');
  } catch {
    return input.replace(/[^a-z0-9.-]+/gi, '_');
  }
}

function render(results: AuditResult[], opts: { json: boolean; hooks: boolean; rate?: number }): string {
  const hourly = opts.rate ? { hourlyRate: opts.rate } : {};
  if (opts.hooks) {
    if (opts.json) return JSON.stringify(results.map((r) => ({ url: r.url, combinedScore: r.combinedScore ?? null, ...buildHooks(r, hourly) })), null, 2);
    return results.map((r) => toHooksMarkdown(r, buildHooks(r, hourly))).join('\n');
  }
  return opts.json ? JSON.stringify(results, null, 2) : toMarkdownReport(results);
}

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      json: { type: 'boolean', default: false },
      out: { type: 'string' },
      'max-bundles': { type: 'string' },
      timeout: { type: 'string' },
      'fail-on': { type: 'string' },
      lighthouse: { type: 'boolean', default: false },
      hooks: { type: 'boolean', default: false },
      rate: { type: 'string' },
      'lighthouse-timeout': { type: 'string' },
      'chrome-path': { type: 'string' },
      'lighthouse-json': { type: 'string' },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });

  if (values.help || positionals.length === 0) {
    console.log(USAGE);
    return values.help ? 0 : 1;
  }

  const failOn = values['fail-on'] as Severity | undefined;
  if (failOn && (failOn === 'info' || !SEVERITY_ORDER.includes(failOn))) {
    throw new Error('--fail-on must be one of critical, high, medium, low');
  }

  const options = {
    maxBundles: positiveInt(values['max-bundles'], 'max-bundles', DEFAULTS.maxBundles),
    timeoutMs: positiveInt(values.timeout, 'timeout', DEFAULTS.timeoutMs),
    // Local tool: auditing your own localhost / staging box is a normal use.
    allowPrivateNetwork: true,
  };

  const useLighthouse = values.lighthouse || values.hooks;
  const lighthouse: LighthouseOptions = {
    timeoutMs: positiveInt(values['lighthouse-timeout'], 'lighthouse-timeout', 60) * 1000,
    ...(values['chrome-path'] ? { chromePath: values['chrome-path'] } : {}),
  };
  const reportDir = values['lighthouse-json'];
  if (reportDir) await mkdir(reportDir, { recursive: true });
  const rate = values.rate === undefined ? undefined : positiveInt(values.rate, 'rate', 0);
  // Loaded only when needed, so the passive audit never pays for Lighthouse's startup.
  const withLighthouse = useLighthouse ? (await import('./lighthouse/index.js')).auditSiteWithLighthouse : undefined;

  const results: AuditResult[] = [];
  for (const url of positionals) {
    console.error(`auditing ${url}${useLighthouse ? ' (with Lighthouse)' : ''} …`);
    const started = Date.now();
    const saveTo = reportDir ? { saveReportTo: join(reportDir, `${reportName(url)}.json`) } : {};
    results.push(withLighthouse ? await withLighthouse(url, options, { ...lighthouse, ...saveTo }) : await auditSite(url, options));
    console.error(`  done in ${((Date.now() - started) / 1000).toFixed(1)} s`);
  }

  const output = render(results, { json: values.json, hooks: values.hooks, ...(rate ? { rate } : {}) });
  console.log(output);
  if (values.out) await writeFile(values.out, `${output}\n`);

  return failOn && failsOn(results, failOn) ? 2 : 0;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    console.error(`launch-audit: ${(err as Error).message}`);
    process.exitCode = 1;
  },
);
