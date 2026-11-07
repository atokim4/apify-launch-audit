#!/usr/bin/env node
import { writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { auditSite, DEFAULTS } from './audit.js';
import { toMarkdownReport } from './report.js';
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

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      json: { type: 'boolean', default: false },
      out: { type: 'string' },
      'max-bundles': { type: 'string' },
      timeout: { type: 'string' },
      'fail-on': { type: 'string' },
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

  const results: AuditResult[] = [];
  for (const url of positionals) {
    console.error(`auditing ${url} …`);
    results.push(await auditSite(url, options));
  }

  const output = values.json ? JSON.stringify(results, null, 2) : toMarkdownReport(results);
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
