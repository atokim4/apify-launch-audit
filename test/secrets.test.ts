import { describe, expect, it } from 'vitest';
import { decodeJwtPayload, redact, scanText } from '../src/secrets.js';
import { FAKE, PEM_HEADER } from './fixtures/keys.js';

describe('scanText', () => {
  it.each([
    ['stripe-live-secret', FAKE.stripeLive],
    ['stripe-live-restricted', FAKE.stripeRestricted],
    ['openai-key', FAKE.openai],
    ['anthropic-key', FAKE.anthropic],
    ['private-key', FAKE.privateKey],
    ['supabase-service-role', FAKE.serviceRole],
  ])('detects %s', (kind, value) => {
    const { secrets } = scanText(`var a = "${value}";`);
    expect(secrets.map((s) => s.kind)).toEqual([kind]);
    expect(secrets[0]?.redacted).not.toContain(value.slice(-16));
    expect(secrets[0]?.redacted.length).toBeLessThan(60);
  });

  it('treats the Supabase anon key as public config, not a secret', () => {
    const { secrets, publicConfig } = scanText(`createClient("${FAKE.supabaseUrl}", "${FAKE.anon}")`);
    expect(secrets).toEqual([]);
    expect(publicConfig).toMatchObject({ supabaseAnonKey: true, supabaseUrls: [FAKE.supabaseUrl] });
  });

  it('ignores placeholders, bare PEM headers and non-Supabase JWTs', () => {
    const text = [FAKE.stripePlaceholder, PEM_HEADER, FAKE.genericJwt].join('\n');
    expect(scanText(text).secrets).toEqual([]);
  });

  it('reports the same key once', () => {
    expect(scanText(`${FAKE.stripeLive} ${FAKE.stripeLive}`).secrets).toHaveLength(1);
  });

  it('reads the Firebase project only when an API key is present', () => {
    expect(scanText('authDomain:"demo.firebaseapp.com"').publicConfig.firebaseProjects).toEqual([]);
    expect(scanText(`apiKey:"${FAKE.firebaseApiKey}",authDomain:"demo.firebaseapp.com"`).publicConfig.firebaseProjects).toEqual(['demo']);
  });
});

describe('redact', () => {
  it('keeps a short prefix and the length', () => {
    expect(redact(FAKE.stripeLive, 12)).toBe(`${FAKE.stripeLive.slice(0, 12)}…[redacted, ${FAKE.stripeLive.length} chars]`);
  });
  it('keeps only the armour line of a PEM key', () => {
    expect(redact(FAKE.privateKey, 0)).toBe(`${PEM_HEADER} …[redacted]`);
  });
});

describe('decodeJwtPayload', () => {
  it('decodes claims and survives garbage', () => {
    expect(decodeJwtPayload(FAKE.serviceRole)?.role).toBe('service_role');
    expect(decodeJwtPayload('eyJ.notjson.x')).toBeNull();
  });
});
