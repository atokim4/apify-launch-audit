# Launch Audit

Give it the URL of a deployed web app and it tells you what a stranger can see from the outside before you launch: missing HTTPS and security headers, weak cookie flags, API keys sitting in your JavaScript bundles, public source maps, an exposed `.env`, a robots.txt that still blocks Google, and how heavy the page is. Every finding comes with a severity and a concrete fix, and the site gets a score from 0 to 100.

It works with any stack, and it was written with AI-built and "vibe-coded" apps in mind (Vite + React, Next.js, Nuxt, Supabase, Firebase, Stripe), where secret keys end up in the frontend more often than people think.

The audit is passive. It only sends ordinary GET requests for the page, its own JavaScript files and a few well-known paths. It never logs in, submits forms, reads a database or tries to exploit anything.

## What it checks

| Area | Checks |
| --- | --- |
| HTTPS | http:// to https:// redirect (and whether it is permanent), invalid certificate, HSTS present and long enough, redirect chain length, mixed content |
| Security headers | Content-Security-Policy (and `'unsafe-inline'` without nonces), clickjacking protection (X-Frame-Options or `frame-ancestors`), X-Content-Type-Options, Referrer-Policy, Permissions-Policy, server version disclosure |
| Cookies | Secure, HttpOnly on session-like cookies, SameSite, `SameSite=None` without Secure. Analytics cookies are ignored. |
| Leaked secrets | Stripe live secret and restricted keys, Stripe test secret keys, Supabase `service_role` JWTs (found by decoding the `role` claim) and `sb_secret_` keys, OpenAI and Anthropic API keys, AWS access key IDs, GitHub tokens, PEM private keys. Values are always shown redacted. |
| Backend config | Supabase URL and anon/publishable key found: reminder to verify Row Level Security. Firebase web config found: reminder to verify Security Rules. |
| Exposure | Public source maps, downloadable `/.env` and `/.git/HEAD`, a Vite dev server running in production |
| SEO basics | robots.txt present and not blocking everything (RFC 9309 rules), sitemap, `noindex`, title, meta description, viewport |
| Performance | Time to first byte, HTML size, JavaScript size, uncompressed text responses |
| Stack | Next.js, Nuxt, Remix, SvelteKit, Astro, Gatsby, Angular, Vite, React, Vue, Svelte, WordPress, Shopify, Wix, Webflow; hosting and CDN from response headers (Vercel, Netlify, Cloudflare, AWS, Fly.io, Render, and others) |

JavaScript scanning follows lazy-loaded chunks: it reads the first-party scripts on the page, then the chunk paths those scripts reference (Vite `assets/`, Next.js `_next/static/`, Nuxt `_nuxt/`, SvelteKit, Astro), up to the `maxBundles` limit. Third-party scripts such as analytics tags are skipped.

### What it does not do

- It does not run a browser, so scripts injected only at runtime by other scripts may be missed, and the timing numbers come from one server-side request, not from a real device.
- It does not test your Supabase RLS policies or Firebase rules. It tells you when you need to check them.
- A clean report is not a penetration test. It covers the common mistakes that are visible from outside.

## Input

```json
{
  "urls": ["https://my-app.example", "staging.my-app.example"],
  "maxBundles": 20,
  "timeoutSecs": 15
}
```

| Field | Default | Meaning |
| --- | --- | --- |
| `urls` | (required) | Up to 100 public URLs. A bare domain is checked over https://. |
| `maxBundles` | 20 | JavaScript files downloaded and scanned per site (1-100). |
| `timeoutSecs` | 15 | Timeout for each HTTP request (5-60). |

Only public sites can be audited on the platform: URLs that resolve to localhost or a private network are refused.

## Output

Each site becomes one dataset row: `url`, `finalUrl`, `score`, `grade`, counts per severity, `frameworks`, `hosting`, `ttfbMs`, `jsKb`, `topIssues`, the full `findings` list (id, category, severity, title, detail, fix, redacted evidence) and `metrics`. A URL that could not be fetched still gets a row, with `error` set.

The whole run is also saved as a Markdown report in the key-value store under `OUTPUT`. This excerpt is from the test fixture in this repository (a fake app with planted, non-working keys):

```markdown
## http://localhost:3000/

**Score: 0/100 (F)** · 7 critical · 1 high · 5 medium · 7 low · 1 to check

### Critical

- **Stripe live secret key exposed in client code**: Anyone who opens the site can read this value from the JavaScript. Treat it as compromised even if you remove it now.
  - Fix: Roll the key in Stripe (Developers → API keys) today, then create Checkout Sessions / PaymentIntents from a server or edge function. The browser only needs the pk_live_ key.
  - `sk_live_GkUA…[redacted, 107 chars]`
  - `in http://localhost:3000/assets/index-Ab12Cd34.js`
```

## Pricing

The Actor itself is free for now: you only pay for Apify platform usage, and a run over a few sites takes a few seconds at 256 MB of memory. If per-site pricing is added later, Apify will announce it in advance; it would be one `site-audited` event per site that was reached and audited, URLs that fail (DNS error, timeout, private address) would not be charged, and runs would stop at your spending limit.

## Scoring

The score starts at 100. Each finding subtracts points by severity: critical 25, high 12, medium 6, low 2. "Check manually" notes subtract nothing. A site with any critical finding is capped at 40, so a leaked live key can never hide behind good headers. Grades: A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, F below that.

## Run it locally

Requires Node.js 22.19 or newer.

```bash
npm install
npx tsx src/cli.ts https://my-app.example
npx tsx src/cli.ts my-app.example other-app.example --json --out report.json
```

Options: `--json`, `--out <file>`, `--max-bundles <n>`, `--timeout <ms>`, and `--fail-on critical|high|medium|low`, which exits with code 2 when a finding at that level or worse exists (handy as a CI step after a preview deploy). The local CLI can also audit `localhost` and staging machines on your own network.

No API keys or environment variables are needed.

## Development

```bash
npm test           # Vitest: unit tests + a local fixture server with planted fake keys
npm run lint       # ESLint (typescript-eslint, strict type-checked)
npm run typecheck
npm run build      # compiles to dist/
```

The fake keys in `test/fixtures/keys.ts` are generated at runtime so the repository never contains a string that looks like a real credential.

To run the Actor locally with the Apify CLI, put an input in `storage/key_value_stores/default/INPUT.json`, then `npm run build && apify run`.

### Layout

```
src/
  audit.ts        collects a snapshot of the site and runs the checks
  http.ts         undici GET with timeouts, size caps and streaming decompression
  network.ts      blocks private and loopback addresses at DNS/connect time
  page.ts         HTML parsing (cheerio), chunk discovery, first-party scope
  secrets.ts      secret patterns, JWT role decoding, redaction
  checks/         one file per area; each is a pure function of the snapshot
  score.ts        severity weights and grade
  report.ts       Markdown report
  cli.ts          command-line entry
  main.ts         Apify Actor entry (input validation, dataset, OUTPUT, pay-per-event)
.actor/           actor.json, input, dataset and output schemas, Dockerfile
test/             Vitest suites and the fixture server
```

## License

MIT
