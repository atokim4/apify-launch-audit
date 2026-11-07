import { SEVERITY_ORDER } from './score.js';
import type { AuditResult, Severity } from './types.js';

const LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Check manually',
};

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
  lines.push(
    `**Score: ${result.score}/100 (${result.grade})** · ${c.critical} critical · ${c.high} high · ${c.medium} medium · ${c.low} low · ${c.info} to check`,
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
