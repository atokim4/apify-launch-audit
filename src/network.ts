import { lookup, type LookupAddress, type LookupOptions } from 'node:dns';
import { lookup as dnsLookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';

const blocked = new BlockList();
for (const [net, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['224.0.0.0', 4],
] as const) {
  blocked.addSubnet(net, prefix, 'ipv4');
}
for (const [net, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['fc00::', 7],
  ['fe80::', 10],
] as const) {
  blocked.addSubnet(net, prefix, 'ipv6');
}

/** True for loopback, private, link-local (cloud metadata) and other non-public addresses. */
export function isPrivateAddress(address: string): boolean {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address)?.[1];
  if (mapped) return isPrivateAddress(mapped);
  const family = isIP(address);
  if (family === 0) return false;
  return blocked.check(address, family === 4 ? 'ipv4' : 'ipv6');
}

export class PrivateNetworkError extends Error {
  readonly code = 'PRIVATE_NETWORK';
  constructor(host: string) {
    super(`${host} resolves to a private or local address; only public sites can be audited`);
    this.name = 'PrivateNetworkError';
  }
}

type LookupCallback = (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void;

/**
 * Drop-in `dns.lookup` for socket connections that refuses private addresses. Because it runs
 * at connect time it also covers redirects and DNS names that point inward.
 */
export function publicOnlyLookup(hostname: string, options: LookupOptions, callback: LookupCallback): void {
  lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) {
      callback(err, []);
      return;
    }
    if (addresses.some((a) => isPrivateAddress(a.address))) {
      callback(new PrivateNetworkError(hostname), []);
      return;
    }
    if (options.all) {
      callback(null, addresses);
      return;
    }
    const first = addresses[0];
    if (!first) {
      callback(Object.assign(new Error(`no address for ${hostname}`), { code: 'ENOTFOUND' }), []);
      return;
    }
    callback(null, first.address, first.family);
  });
}

/** Rejects URLs whose host is a literal private IP (those never reach the DNS lookup). */
export function assertPublicLiteral(url: string): void {
  const host = new URL(url).hostname.replace(/^\[|\]$/g, '');
  if (host === 'localhost' || host.endsWith('.localhost') || isPrivateAddress(host)) {
    throw new PrivateNetworkError(host);
  }
}

/** Resolves the host and rejects it when any address is private. For tools that open their own connections (Chrome). */
export async function assertPublicHost(url: string): Promise<void> {
  assertPublicLiteral(url);
  const host = new URL(url).hostname.replace(/^\[|\]$/g, '');
  if (isIP(host) !== 0) return;
  const addresses = await dnsLookup(host, { all: true });
  if (addresses.some((a) => isPrivateAddress(a.address))) throw new PrivateNetworkError(host);
}
