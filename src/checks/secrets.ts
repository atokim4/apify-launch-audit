import type { SecretMatch } from '../secrets.js';
import type { SiteSnapshot } from '../snapshot.js';
import type { Finding } from '../types.js';

const GENERIC_FIX =
  'Rotate the key in the provider dashboard today, move the call that needs it to a server/edge function, and keep only publishable keys in the frontend.';

const FIX: Partial<Record<SecretMatch['kind'], string>> = {
  'stripe-live-secret':
    'Roll the key in Stripe (Developers → API keys) today, then create Checkout Sessions / PaymentIntents from a server or edge function. The browser only needs the pk_live_ key.',
  'stripe-live-restricted': 'Roll the restricted key in Stripe today and call the Stripe API only from server code.',
  'supabase-service-role':
    'This key bypasses Row Level Security. Rotate the JWT secret / service_role key in Supabase project settings today and run privileged queries from an Edge Function; the browser should only get the anon key.',
  'supabase-secret-key':
    'Delete and recreate the secret key in Supabase project settings today; the browser should only get the publishable key.',
  'private-key':
    'Revoke this key pair wherever it is trusted (certificate, SSH, JWT signing, service account), issue a new one, and keep it on the server only.',
};

interface Located {
  match: SecretMatch;
  urls: string[];
}

function sources(s: SiteSnapshot): { url: string; scan: NonNullable<SiteSnapshot['inlineScan']> }[] {
  const list = s.bundles.map((b) => ({ url: b.url, scan: b.scan }));
  if (s.inlineScan) list.unshift({ url: `${s.finalUrl} (inline HTML)`, scan: s.inlineScan });
  return list;
}

export function checkSecrets(s: SiteSnapshot): Finding[] {
  const found = new Map<string, Located>();
  const supabaseUrls = new Set<string>();
  const firebaseProjects = new Set<string>();
  let anonKey = false;

  for (const { url, scan } of sources(s)) {
    for (const match of scan.secrets) {
      const entry = found.get(match.fingerprint) ?? { match, urls: [] };
      entry.urls.push(url);
      found.set(match.fingerprint, entry);
    }
    scan.publicConfig.supabaseUrls.forEach((u) => supabaseUrls.add(u));
    scan.publicConfig.firebaseProjects.forEach((p) => firebaseProjects.add(p));
    anonKey ||= scan.publicConfig.supabaseAnonKey;
  }

  const findings: Finding[] = [];
  for (const { match, urls } of found.values()) {
    findings.push({
      id: `secrets.${match.kind}`,
      category: 'secrets',
      severity: match.severity,
      title: `${match.label} exposed in client code`,
      detail:
        'Anyone who opens the site can read this value from the JavaScript. Treat it as compromised even if you remove it now.',
      fix: FIX[match.kind] ?? GENERIC_FIX,
      evidence: [match.redacted, ...urls.slice(0, 3).map((u) => `in ${u}`)],
    });
  }

  if (supabaseUrls.size > 0 || anonKey) {
    findings.push({
      id: 'backend.supabase-verify-rls',
      category: 'backend',
      severity: 'info',
      title: 'Supabase project and public key found: verify Row Level Security',
      detail:
        'The anon/publishable key is meant to be public, so every table is only as safe as its RLS policies. This audit does not query your database.',
      fix: 'In the Supabase dashboard, run Security Advisor and make sure RLS is enabled with explicit policies on every table in the exposed schemas; test with the anon key that other users’ rows are not readable.',
      evidence: [...supabaseUrls].slice(0, 3),
    });
  }

  if (firebaseProjects.size > 0) {
    findings.push({
      id: 'backend.firebase-verify-rules',
      category: 'backend',
      severity: 'info',
      title: 'Firebase config found: verify Security Rules',
      detail: 'Firebase web config is public by design; access control lives entirely in Firestore/Storage/RTDB rules.',
      fix: 'Check that no rule is `allow read, write: if true` and that rules require `request.auth` and ownership; enable App Check.',
      evidence: [...firebaseProjects].map((p) => `project: ${p}`),
    });
  }

  const maps = s.bundles.filter((b) => b.publicSourceMap);
  if (maps.length > 0) {
    findings.push({
      id: 'exposure.source-maps',
      category: 'exposure',
      severity: 'medium',
      title: `Source maps are public (${maps.length})`,
      detail: 'Anyone can download your original, unminified source code, comments and internal paths.',
      fix: 'Disable production browser source maps (Vite `build.sourcemap: false`, Next `productionBrowserSourceMaps: false`) or upload them only to your error tracker.',
      evidence: maps.slice(0, 5).map((b) => b.publicSourceMap ?? ''),
    });
  }

  for (const file of s.exposedFiles) {
    findings.push({
      id: `exposure.${file.path === '/.env' ? 'env-file' : 'git-dir'}`,
      category: 'exposure',
      severity: 'critical',
      title: `${file.path} is publicly downloadable`,
      detail:
        file.path === '/.env'
          ? 'The environment file (usually database URLs and API secrets) is served to anyone. Contents were not stored by this audit.'
          : 'The .git directory is served, so the full source and history can be reconstructed.',
      fix: 'Block dotfiles at the web server/CDN, remove the file from the deploy output, and rotate every secret it contained.',
      evidence: [file.url],
    });
  }

  return findings;
}
