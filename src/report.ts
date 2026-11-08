import type { HookReport } from './hooks.js';
import { SEVERITY_ORDER } from './score.js';
import type { AuditResult, LighthouseFailure, LighthouseSummary, Severity } from './types.js';

const LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Check manually',
};

const secs = (ms: number | null): string => (ms === null ? '-' : `${(ms / 1000).toFixed(1)} s`);
const num = (value: number | null): string => (value === null ? '-' : String(value));

function lighthouseSection(lh: LighthouseSummary | LighthouseFailure): string[] {
  if ('error' in lh) return [`Lighthouse did not run: ${lh.error}`, ''];
  const s = lh.scores;
  const lines = [
    `### Lighthouse (${lh.formFactor}, Lighthouse ${lh.lighthouseVersion}, ${secs(lh.durationMs)})`,
    '',
    '| Performance | Accessibility | Best practices | SEO |',
    '| --- | --- | --- | --- |',
    `| ${num(s.performance)} | ${num(s.accessibility)} | ${num(s.bestPractices)} | ${num(s.seo)} |`,
    '',
    '| Metric | Value | Good |',
    '| --- | --- | --- |',
    `| Largest Contentful Paint | ${secs(lh.lcpMs)} | ≤ 2.5 s |`,
    `| Total Blocking Time | ${lh.tbtMs === null ? '-' : `${lh.tbtMs} ms`} | ≤ 200 ms |`,
    `| Cumulative Layout Shift | ${lh.cls === null ? '-' : lh.cls.toFixed(3)} | ≤ 0.1 |`,
    `| First Contentful Paint | ${secs(lh.fcpMs)} | ≤ 1.8 s |`,
    `| JavaScript (transferred) | ${lh.jsKb === null ? '-' : `${lh.jsKb} KB in ${lh.jsRequests ?? '?'} file(s)`} | |`,
    `| Page total (transferred) | ${lh.totalKb === null ? '-' : `${lh.totalKb} KB`} | |`,
    '',
  ];
  if (lh.opportunities.length > 0) {
    lines.push('Biggest opportunities:', '');
    for (const o of lh.opportunities) {
      const parts = [o.savingsMs > 0 ? `~${secs(o.savingsMs)}` : '', o.savingsBytes > 0 ? kb(o.savingsBytes) : ''].filter(Boolean);
      lines.push(`- ${o.title}: ${parts.join(', ')}`);
    }
    lines.push('');
  }
  for (const w of lh.warnings) lines.push(`> Lighthouse warning: ${w}`, '');
  return lines;
}

const kb = (bytes: number): string => `${(bytes / 1024).toFixed(bytes < 10_240 ? 1 : 0)} KB`;

/** Escapes characters that would break a Markdown table cell or inline code. */
const cell = (text: string): string => text.replace(/\|/g, '\\|').replace(/`/g, "'");

export function toMarkdown(result: AuditResult): string {
  const lines: string[] = [`## ${result.url}`, ''];
  if (result.error) {
    lines.push(`Could not audit this URL: ${result.error}`, '');
    for (const f of result.findings) lines.push(`- **${f.title}**: ${f.detail}`, `  - Fix: ${f.fix}`, '');
    return lines.join('\n');
  }

  const c = result.counts;
  const combined = result.combinedScore !== undefined ? ` · combined with Lighthouse: ${result.combinedScore}/100` : '';
  lines.push(
    `**Score: ${result.score}/100 (${result.grade})**${combined} · ${c.critical} critical · ${c.high} high · ${c.medium} medium · ${c.low} low · ${c.info} to check`,
    '',
    `Final URL: ${result.finalUrl ?? '-'}  `,
    `Stack: ${result.stack.frameworks.join(', ') || 'not detected'} · Hosting: ${result.stack.hosting.join(', ') || 'not detected'}`,
    '',
    '| Metric | Value |',
    '| --- | --- |',
    `| Time to first byte | ${result.metrics.ttfbMs ?? '-'} ms |`,
    `| HTML | ${kb(result.metrics.htmlBytes)} (${kb(result.metrics.htmlTransferBytes)} transferred) |`,
    `| Redirects | ${result.metrics.redirects} |`,
    `| Scripts / stylesheets / images in HTML | ${result.metrics.scriptsReferenced} / ${result.metrics.stylesheetsReferenced} / ${result.metrics.imagesReferenced} |`,
    `| JS scanned | ${result.metrics.scriptsScanned} file(s), ${kb(result.metrics.jsBytes)} (${kb(result.metrics.jsTransferBytes)} transferred) |`,
    '',
  );
  if (result.lighthouse) lines.push(...lighthouseSection(result.lighthouse));

  if (result.findings.length === 0) {
    lines.push('No issues found by the passive checks.', '');
    return lines.join('\n');
  }

  for (const severity of SEVERITY_ORDER) {
    const group = result.findings.filter((f) => f.severity === severity);
    if (group.length === 0) continue;
    lines.push(`### ${LABEL[severity]}`, '');
    for (const f of group) {
      lines.push(`- **${f.title}**: ${f.detail}`, `  - Fix: ${f.fix}`);
      for (const e of f.evidence ?? []) lines.push(`  - \`${cell(e)}\``);
    }
    lines.push('');
  }
  return lines.join('\n');
}

export function toMarkdownReport(results: AuditResult[]): string {
  const header = [
    '# Launch audit report',
    '',
    `Generated ${new Date().toISOString()} · passive checks only (no login, no database access, no form submissions).`,
    '',
  ];
  return [...header, ...results.map(toMarkdown)].join('\n');
}

/** Short per-site summary: scores, the strongest hooks as plain sentences, and the fix scope. */
export function toHooksMarkdown(result: AuditResult, report: HookReport): string {
  const lines = [`## ${result.url}`, ''];
  if (result.error) lines.push(`Could not audit this URL: ${result.error}`, '');
  const lh = result.lighthouse && !('error' in result.lighthouse) ? result.lighthouse : undefined;
  if (!result.error) {
    if (lh && result.combinedScore !== undefined) {
      const s = lh.scores;
      lines.push(
        `Combined score ${result.combinedScore}/100 (security ${result.score}, mobile speed ${num(s.performance)}, accessibility ${num(s.accessibility)}, best practices ${num(s.bestPractices)}, SEO ${num(s.seo)})`,
        '',
      );
    } else {
      lines.push(`Security score ${result.score}/100`, '');
    }
  }
  if (result.lighthouse && 'error' in result.lighthouse) lines.push(`Speed not measured: ${result.lighthouse.error}`, '');
  if (report.hooks.length === 0) {
    if (!result.error) {
      const speed = lh ? ' and the page loads fast on a phone' : '';
      lines.push(`Nothing strong enough to lead with: no serious security issue found${speed}.`, '');
    }
    return lines.join('\n');
  }
  report.hooks.forEach((h, i) => lines.push(`${i + 1}. ${h.sentence}`));
  lines.push('', report.scope ?? '', '');
  return lines.join('\n');
}
