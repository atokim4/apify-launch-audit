import { constants } from 'node:fs';
import { access, writeFile } from 'node:fs/promises';
import { launch, type LaunchedChrome } from 'chrome-launcher';
import lighthouse from 'lighthouse';
import { type LhrLike, summarizeLhr } from './summary.js';
import type { LighthouseFailure, LighthouseSummary } from '../types.js';

export interface LighthouseOptions {
  /** Hard limit for Chrome start + page load + audits. */
  timeoutMs?: number;
  /** Chrome/Chromium binary. Falls back to $CHROME_PATH, then chrome-launcher's own search. */
  chromePath?: string;
  /** Also write the full Lighthouse JSON report here (open it in the Lighthouse viewer). */
  saveReportTo?: string;
}

export const LIGHTHOUSE_DEFAULTS = { timeoutMs: 60_000 } as const;

const CATEGORIES = ['performance', 'accessibility', 'best-practices', 'seo'];
/**
 * Time kept free after the page-load wait. Pages that never go network-idle (chat widgets,
 * polling) use the whole wait, then Lighthouse spends ~12 s checking whether the page hung and
 * ~10-20 s gathering artifacts and auditing.
 */
const AFTER_LOAD_BUDGET_MS = 35_000;
const MIN_LOAD_WAIT_MS = 10_000;

class TimeoutError extends Error {
  constructor(ms: number) {
    super(`Lighthouse did not finish within ${Math.round(ms / 1000)} s`);
    this.name = 'TimeoutError';
  }
}

/**
 * `--no-sandbox`: Chrome's sandbox needs user namespaces or a setuid helper, which containers and
 * many servers do not have, and it cannot run as root at all. The browser here is a throwaway
 * headless profile in a temp directory that only loads the audited page.
 */
const CHROME_FLAGS = ['--headless=new', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--no-first-run'];

class ChromeNotFoundError extends Error {
  constructor(detail: string) {
    super(`Chrome was not found (${detail}); install Google Chrome or Chromium, or set CHROME_PATH`);
    this.name = 'ChromeNotFoundError';
  }
}

/** chrome-launcher crashes the process on a bad binary path (unhandled spawn error), so check it first. */
async function assertExecutable(path: string): Promise<void> {
  try {
    await access(path, constants.X_OK);
  } catch {
    throw new ChromeNotFoundError(`${path} is not an executable file`);
  }
}

function withTimeout<T>(work: Promise<T>, ms: number, onTimeout: () => void): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      onTimeout();
      reject(new TimeoutError(ms));
    }, ms);
  });
  return Promise.race([work, timeout]).finally(() => {
    clearTimeout(timer);
  });
}

interface AuditJob {
  url: string;
  timeoutMs: number;
  chromePath: string | undefined;
  saveReportTo: string | undefined;
  onChrome: (chrome: LaunchedChrome) => void;
}

async function audit({ url, timeoutMs, chromePath, saveReportTo, onChrome }: AuditJob): Promise<LhrLike> {
  if (chromePath) await assertExecutable(chromePath);
  const chrome = await launch({ chromeFlags: CHROME_FLAGS, logLevel: 'silent', ...(chromePath ? { chromePath } : {}) });
  onChrome(chrome);
  const result = await lighthouse(url, {
    port: chrome.port,
    output: 'json',
    logLevel: 'error',
    onlyCategories: CATEGORIES,
    maxWaitForLoad: Math.max(MIN_LOAD_WAIT_MS, timeoutMs - AFTER_LOAD_BUDGET_MS),
    // The full-page screenshot takes seconds on long pages and nothing here uses it.
    disableFullPageScreenshot: true,
  });
  if (!result) throw new Error('Lighthouse returned no result');
  if (saveReportTo && typeof result.report === 'string') await writeFile(saveReportTo, result.report);
  return result.lhr as unknown as LhrLike;
}

/**
 * Runs Lighthouse (mobile preset: simulated mid-range phone on slow 4G) against one URL.
 * Never throws: a missing Chrome, a crash or a timeout comes back as `{ error }` so the
 * passive audit can still be reported.
 */
export async function runLighthouse(url: string, options: LighthouseOptions = {}): Promise<LighthouseSummary | LighthouseFailure> {
  const timeoutMs = options.timeoutMs ?? LIGHTHOUSE_DEFAULTS.timeoutMs;
  const chromePath = options.chromePath ?? process.env.CHROME_PATH;
  const started = Date.now();
  let chrome: LaunchedChrome | undefined;
  let timedOut = false;
  const kill = (): void => {
    chrome?.kill();
  };
  try {
    const lhr = await withTimeout(
      audit({
        url,
        timeoutMs,
        chromePath,
        saveReportTo: options.saveReportTo,
        onChrome: (c) => {
          chrome = c;
          if (timedOut) kill();
        },
      }),
      timeoutMs,
      () => {
        timedOut = true;
        kill();
      },
    );
    return summarizeLhr(lhr, Date.now() - started);
  } catch (err) {
    return { error: describe(err), durationMs: Date.now() - started };
  } finally {
    kill();
  }
}

function describe(err: unknown): string {
  if (err instanceof ChromeNotFoundError || err instanceof TimeoutError) return err.message;
  const message = err instanceof Error ? err.message : String(err);
  const code = (err as { code?: unknown } | null)?.code;
  if (code === 'ERR_LAUNCHER_NOT_INSTALLED' || /No Chrome installations found/i.test(message)) {
    return new ChromeNotFoundError('no installation detected').message;
  }
  return `Lighthouse failed: ${message.split('\n')[0] ?? message}`;
}

export function isLighthouseFailure(value: LighthouseSummary | LighthouseFailure | undefined): value is LighthouseFailure {
  return value !== undefined && 'error' in value;
}
