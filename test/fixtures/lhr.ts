import { readFileSync } from 'node:fs';
import type { LhrLike } from '../../src/lighthouse/summary.js';

export type LhrFixture = 'fast' | 'frozen' | 'layout-shift' | 'slow-images';

/** Trimmed real Lighthouse 13.6 reports (mobile) from public sites, URLs replaced. See scripts/trim-lhr.ts. */
export function loadLhr(name: LhrFixture): LhrLike {
  return JSON.parse(readFileSync(new URL(`./lhr/${name}.json`, import.meta.url), 'utf8')) as LhrLike;
}
