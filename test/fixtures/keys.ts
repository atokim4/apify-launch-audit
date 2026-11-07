/**
 * Fake credentials for tests. They are assembled at runtime so the repository never contains a
 * string that looks like a real key to secret scanners. None of them work anywhere.
 */
const body = (seed: number, length: number): string => {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let out = '';
  let state = seed;
  for (let i = 0; i < length; i++) {
    state = (state * 1103515245 + 12345) % 2147483648;
    out += alphabet.charAt(state % alphabet.length);
  }
  return out;
};

const b64url = (value: object): string => Buffer.from(JSON.stringify(value)).toString('base64url');
const jwt = (claims: object): string =>
  `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url(claims)}.${body(99, 43)}`;

/** PEM armour line, e.g. what a PEM-parsing library contains as a constant. */
export const PEM_HEADER = ['-----BEGIN', 'PRIVATE', 'KEY-----'].join(' ');

export const FAKE = {
  stripeLive: ['sk', 'live', body(1, 99)].join('_'),
  stripeRestricted: ['rk', 'live', body(2, 99)].join('_'),
  stripePlaceholder: ['sk', 'live', 'x'.repeat(24)].join('_'),
  openai: ['sk', 'proj', body(3, 58)].join('-') + ['T3Blbk', 'FJ'].join('') + body(4, 58),
  anthropic: ['sk', 'ant', 'api03', body(5, 93)].join('-') + 'AA',
  privateKey: `${PEM_HEADER}\\n${body(6, 64)}\\n`,
  serviceRole: jwt({ iss: 'supabase', ref: 'abcdefghijklmnopqrst', role: 'service_role', iat: 1700000000 }),
  anon: jwt({ iss: 'supabase', ref: 'abcdefghijklmnopqrst', role: 'anon', iat: 1700000000 }),
  /** A non-Supabase JWT (the jwt.io sample shape). */
  genericJwt: jwt({ sub: '1234567890', name: 'Sample User' }),
  supabaseUrl: 'https://abcdefghijklmnopqrst.supabase.co',
  firebaseApiKey: 'AIza' + body(7, 35),
};
