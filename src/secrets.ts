import type { Severity } from './types.js';

export type SecretKind =
  | 'stripe-live-secret'
  | 'stripe-live-restricted'
  | 'stripe-test-secret'
  | 'supabase-service-role'
  | 'supabase-secret-key'
  | 'openai-key'
  | 'anthropic-key'
  | 'aws-access-key'
  | 'github-token'
  | 'private-key';

export interface SecretMatch {
  kind: SecretKind;
  label: string;
  severity: Severity;
  /** Masked value, safe to print. The raw value is never stored. */
  redacted: string;
  /** Stable fingerprint for de-duplication (not reversible to the key). */
  fingerprint: string;
}

interface Pattern {
  kind: SecretKind;
  label: string;
  severity: Severity;
  regex: RegExp;
  /** Characters of the match kept visible when redacting. */
  keep: number;
}

const PATTERNS: Pattern[] = [
  { kind: 'stripe-live-secret', label: 'Stripe live secret key', severity: 'critical', regex: /\bsk_live_[0-9a-zA-Z]{20,}\b/g, keep: 12 },
  { kind: 'stripe-live-restricted', label: 'Stripe live restricted key', severity: 'critical', regex: /\brk_live_[0-9a-zA-Z]{20,}\b/g, keep: 12 },
  { kind: 'stripe-test-secret', label: 'Stripe test secret key', severity: 'medium', regex: /\bsk_test_[0-9a-zA-Z]{20,}\b/g, keep: 12 },
  { kind: 'supabase-secret-key', label: 'Supabase secret API key', severity: 'critical', regex: /\bsb_secret_[0-9a-zA-Z_-]{20,}/g, keep: 14 },
  {
    kind: 'openai-key',
    label: 'OpenAI API key',
    severity: 'critical',
    regex: /\bsk-(?:(?:proj|svcacct|admin)-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}/g,
    keep: 10,
  },
  { kind: 'anthropic-key', label: 'Anthropic API key', severity: 'critical', regex: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{60,}/g, keep: 14 },
  { kind: 'aws-access-key', label: 'AWS access key ID', severity: 'high', regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, keep: 8 },
  { kind: 'github-token', label: 'GitHub token', severity: 'critical', regex: /\b(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{36,}\b/g, keep: 8 },
  {
    kind: 'private-key',
    label: 'Private key (PEM)',
    severity: 'critical',
    // Header followed by a base64 body, so PEM-parsing library code does not match.
    regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----(?:\\n|\\r|\s)+[A-Za-z0-9+/=]{40,}/g,
    keep: 0,
  },
];

const PLACEHOLDER = /x{6,}|EXAMPLE|your[_-]?(?:key|secret)|0{12,}|1234567890abcdef/i;

const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}/g;

export function redact(value: string, keep: number): string {
  if (keep === 0) {
    const header = /-----BEGIN [A-Z ]+-----/.exec(value);
    return `${header?.[0] ?? '[key]'} …[redacted]`;
  }
  const visible = Math.min(keep, Math.floor(value.length / 3));
  return `${value.slice(0, visible)}…[redacted, ${value.length} chars]`;
}

/** Short non-cryptographic fingerprint (FNV-1a) used only to de-duplicate matches. */
export function fingerprint(value: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < value.length; i++) {
    hash ^= value.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(16).padStart(8, '0');
}

export interface JwtClaims {
  role?: string;
  iss?: string;
  ref?: string;
  [claim: string]: unknown;
}

export function decodeJwtPayload(token: string): JwtClaims | null {
  const part = token.split('.')[1];
  if (!part) return null;
  try {
    const json = Buffer.from(part, 'base64url').toString('utf8');
    const claims: unknown = JSON.parse(json);
    return claims && typeof claims === 'object' ? (claims as JwtClaims) : null;
  } catch {
    return null;
  }
}

export interface PublicConfig {
  supabaseUrls: string[];
  supabaseAnonKey: boolean;
  firebaseProjects: string[];
}

export interface ScanResult {
  secrets: SecretMatch[];
  publicConfig: PublicConfig;
}

function isSupabaseJwt(claims: JwtClaims): boolean {
  return (claims.iss ?? '').includes('supabase') || typeof claims.ref === 'string';
}

/** Finds leaked secrets and public backend config in one JS / HTML text. */
export function scanText(text: string): ScanResult {
  const secrets: SecretMatch[] = [];
  const seen = new Set<string>();
  const add = (kind: SecretKind, label: string, severity: Severity, value: string, keep: number, note = ''): void => {
    const fp = fingerprint(value);
    if (seen.has(fp)) return;
    seen.add(fp);
    secrets.push({ kind, label, severity, redacted: `${redact(value, keep)}${note}`, fingerprint: fp });
  };

  for (const p of PATTERNS) {
    for (const m of text.matchAll(p.regex)) {
      if (PLACEHOLDER.test(m[0])) continue;
      add(p.kind, p.label, p.severity, m[0], p.keep);
    }
  }

  let supabaseAnonKey = /\bsb_publishable_[A-Za-z0-9_-]{20,}/.test(text);
  for (const m of text.matchAll(JWT)) {
    const claims = decodeJwtPayload(m[0]);
    if (!claims || !isSupabaseJwt(claims)) continue;
    if (claims.role === 'service_role') {
      add('supabase-service-role', 'Supabase service_role key', 'critical', m[0], 12, ' (JWT role: service_role)');
    } else if (claims.role === 'anon') {
      supabaseAnonKey = true;
    }
  }

  const supabaseUrls = [...new Set([...text.matchAll(/https:\/\/([a-z0-9]{20})\.supabase\.co\b/g)].map((m) => m[0]))];

  const firebaseProjects = new Set<string>();
  if (/AIza[0-9A-Za-z_-]{35}/.test(text)) {
    for (const m of text.matchAll(/["'`]?authDomain["'`]?\s*:\s*["'`]([a-z0-9-]+)\.firebaseapp\.com/g)) {
      if (m[1]) firebaseProjects.add(m[1]);
    }
  }

  return {
    secrets,
    publicConfig: { supabaseUrls, supabaseAnonKey, firebaseProjects: [...firebaseProjects] },
  };
}
