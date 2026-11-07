import type { Transform } from 'node:stream';
import { constants as zlibConstants, createBrotliDecompress, createGunzip, createInflate } from 'node:zlib';
import { performance } from 'node:perf_hooks';
import { Agent, request } from 'undici';
import { assertPublicLiteral, publicOnlyLookup } from './network.js';
import type { RedirectHop } from './types.js';

export interface HttpResponse {
  url: string;
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  body: Buffer;
  /** Bytes received on the wire (before decompression). */
  transferBytes: number;
  ttfbMs: number;
  truncated: boolean;
}

export interface FetchOptions {
  timeoutMs: number;
  maxBytes: number;
  userAgent: string;
  /** Allow localhost and private ranges (CLI use). The Apify Actor keeps this off. */
  allowPrivateNetwork: boolean;
}

/** One GET without following redirects; `maxBytes` overrides the default body cap. */
export type Fetcher = (url: string, maxBytes?: number) => Promise<HttpResponse>;

export class FetchError extends Error {
  constructor(
    message: string,
    readonly url: string,
    readonly code?: string,
  ) {
    super(message);
    this.name = 'FetchError';
  }
}

const TLS_CODES = new Set([
  'CERT_HAS_EXPIRED',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'CERT_NOT_YET_VALID',
]);

export function isTlsError(err: unknown): boolean {
  return err instanceof FetchError && err.code !== undefined && TLS_CODES.has(err.code);
}

function decompressor(encoding: string | undefined): Transform | null {
  switch (encoding?.trim().toLowerCase()) {
    case 'gzip':
    case 'x-gzip':
      return createGunzip({ finishFlush: zlibConstants.Z_SYNC_FLUSH });
    case 'deflate':
      return createInflate({ finishFlush: zlibConstants.Z_SYNC_FLUSH });
    case 'br':
      return createBrotliDecompress({ finishFlush: zlibConstants.BROTLI_OPERATION_FLUSH });
    default:
      return null;
  }
}

/**
 * Decompresses at most `maxBytes` of output. Tolerates a cut-off input, so a body that hit
 * the download cap still yields its readable prefix.
 */
async function decode(raw: Buffer, encoding: string | undefined, maxBytes: number): Promise<{ body: Buffer; truncated: boolean }> {
  const stream = decompressor(encoding);
  if (!stream) return { body: raw, truncated: false };
  const chunks: Buffer[] = [];
  let size = 0;
  return new Promise((resolve, reject) => {
    const finish = (truncated: boolean): void => {
      resolve({ body: Buffer.concat(chunks).subarray(0, maxBytes), truncated });
    };
    stream.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
      size += chunk.length;
      if (size >= maxBytes) {
        stream.destroy();
        finish(true);
      }
    });
    stream.on('end', () => {
      finish(false);
    });
    stream.on('error', (err) => {
      if (size > 0) finish(true);
      else reject(err);
    });
    stream.end(raw);
  });
}

function flattenHeaders(headers: Record<string, string | string[] | undefined>): {
  headers: Record<string, string>;
  setCookies: string[];
} {
  const flat: Record<string, string> = {};
  let setCookies: string[] = [];
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    const name = key.toLowerCase();
    if (name === 'set-cookie') {
      setCookies = Array.isArray(value) ? value : [value];
      continue;
    }
    flat[name] = Array.isArray(value) ? value.join(', ') : value;
  }
  return { headers: flat, setCookies };
}

/** One GET without following redirects. Body is decompressed and capped at `maxBytes`. */
export function createFetcher(options: FetchOptions): Fetcher {
  const dispatcher = options.allowPrivateNetwork ? undefined : new Agent({ connect: { lookup: publicOnlyLookup } });
  return async (url, maxBytes = options.maxBytes) => {
    if (!options.allowPrivateNetwork) {
      try {
        assertPublicLiteral(url);
      } catch (err) {
        throw new FetchError((err as Error).message, url, 'PRIVATE_NETWORK');
      }
    }
    const started = performance.now();
    let res;
    try {
      res = await request(url, {
        ...(dispatcher ? { dispatcher } : {}),
        method: 'GET',
        headers: {
          'user-agent': options.userAgent,
          accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
          'accept-encoding': 'gzip, deflate, br',
        },
        headersTimeout: options.timeoutMs,
        bodyTimeout: options.timeoutMs,
        signal: AbortSignal.timeout(options.timeoutMs * 2),
      });
    } catch (err) {
      const e = err as NodeJS.ErrnoException & { cause?: NodeJS.ErrnoException };
      const code = e.code ?? e.cause?.code;
      throw new FetchError(`${code ?? e.name}: ${e.message}`, url, code);
    }
    const ttfbMs = Math.round(performance.now() - started);

    const chunks: Buffer[] = [];
    let received = 0;
    let truncated = false;
    try {
      for await (const chunk of res.body) {
        const buf = chunk as Buffer;
        received += buf.length;
        if (received > maxBytes) {
          truncated = true;
          chunks.push(buf.subarray(0, buf.length - (received - maxBytes)));
          res.body.destroy();
          break;
        }
        chunks.push(buf);
      }
    } catch (err) {
      throw new FetchError(`body read failed: ${(err as Error).message}`, url);
    }

    const { headers, setCookies } = flattenHeaders(res.headers);
    const raw = Buffer.concat(chunks);
    let body: Buffer;
    try {
      const decoded = await decode(raw, headers['content-encoding'], maxBytes);
      body = decoded.body;
      truncated ||= decoded.truncated;
    } catch (err) {
      throw new FetchError(`cannot decode ${headers['content-encoding']} body: ${(err as Error).message}`, url);
    }
    return {
      url,
      status: res.statusCode,
      headers,
      setCookies,
      body,
      transferBytes: Math.min(received, maxBytes),
      ttfbMs,
      truncated,
    };
  };
}

export interface RedirectResult {
  chain: RedirectHop[];
  response: HttpResponse;
  /** Every Set-Cookie seen along the chain, with the URL that set it. */
  cookies: { url: string; header: string }[];
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export async function followRedirects(
  fetcher: Fetcher,
  startUrl: string,
  maxHops = 10,
): Promise<RedirectResult> {
  const chain: RedirectHop[] = [];
  const cookies: { url: string; header: string }[] = [];
  let url = startUrl;
  for (let hop = 0; hop <= maxHops; hop++) {
    const response = await fetcher(url);
    for (const header of response.setCookies) cookies.push({ url, header });
    const location = response.headers.location;
    if (!REDIRECT_STATUSES.has(response.status) || !location) {
      return { chain, response, cookies };
    }
    const next = new URL(location, url).toString();
    chain.push({ url, status: response.status, location: next });
    url = next;
  }
  throw new FetchError(`more than ${maxHops} redirects`, startUrl, 'TOO_MANY_REDIRECTS');
}

export function textOf(res: HttpResponse): string {
  return res.body.toString('utf8');
}

export function isHtml(res: HttpResponse): boolean {
  const type = res.headers['content-type'] ?? '';
  if (type.includes('html')) return true;
  return !type && /^\s*<(!doctype html|html)/i.test(res.body.subarray(0, 200).toString('utf8'));
}
