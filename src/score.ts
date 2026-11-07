import type { AuditResult, Finding, Severity } from './types.js';

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

const PENALTY: Record<Severity, number> = { critical: 25, high: 12, medium: 6, low: 2, info: 0 };

/** A site with any critical finding never scores above this. */
const CRITICAL_CAP = 40;

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

export function score(findings: Finding[]): number {
  const raw = 100 - findings.reduce((sum, f) => sum + PENALTY[f.severity], 0);
  const capped = findings.some((f) => f.severity === 'critical') ? Math.min(raw, CRITICAL_CAP) : raw;
  return Math.max(0, Math.min(100, capped));
}

export function grade(value: number): AuditResult['grade'] {
  if (value >= 90) return 'A';
  if (value >= 80) return 'B';
  if (value >= 65) return 'C';
  if (value >= 50) return 'D';
  return 'F';
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
}
