import { describe, expect, it } from 'vitest';
import { isPrivateAddress, publicOnlyLookup } from '../src/network.js';

describe('isPrivateAddress', () => {
  it.each(['127.0.0.1', '10.0.0.5', '172.20.1.1', '192.168.1.1', '169.254.169.254', '::1', 'fd00::1', '::ffff:10.0.0.1'])(
    'blocks %s',
    (ip) => {
      expect(isPrivateAddress(ip)).toBe(true);
    },
  );
  it.each(['93.184.215.14', '1.1.1.1', '2606:4700::1111'])('allows %s', (ip) => {
    expect(isPrivateAddress(ip)).toBe(false);
  });
});

describe('publicOnlyLookup', () => {
  it('rejects names that resolve to loopback', async () => {
    const err = await new Promise((resolve) => {
      publicOnlyLookup('localhost', {}, (e) => {
        resolve(e);
      });
    });
    expect(err).toMatchObject({ code: 'PRIVATE_NETWORK' });
  });
});
