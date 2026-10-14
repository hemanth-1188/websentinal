import { validateTargetUrl, isRestrictedIp } from '../src/security/ssrfGuardian';

describe('Scanner Security & SSRF Protection Unit Tests', () => {
  test('Blocks Carrier-Grade NAT (100.64.0.0/10)', () => {
    expect(isRestrictedIp('100.64.1.1')).toBe(true);
    expect(isRestrictedIp('100.100.1.1')).toBe(true);
  });

  test('Blocks 172.16.0.0/12 private ranges', () => {
    expect(isRestrictedIp('172.16.0.1')).toBe(true);
    expect(isRestrictedIp('172.31.255.254')).toBe(true);
    expect(isRestrictedIp('172.32.0.1')).toBe(false); // Public IP
  });

  test('Blocks 192.168.0.0/16 private range', () => {
    expect(isRestrictedIp('192.168.1.1')).toBe(true);
    expect(isRestrictedIp('192.168.254.254')).toBe(true);
  });

  test('Blocks IPv6 loopback, link-local, and unique-local addresses', () => {
    expect(isRestrictedIp('::1')).toBe(true);
    expect(isRestrictedIp('fe80::1ff:fe23:4567')).toBe(true);
    expect(isRestrictedIp('fc00::1')).toBe(true);
    expect(isRestrictedIp('fd12:3456:789a::1')).toBe(true);
  });

  test('Blocks cloud metadata hostname (metadata.google.internal)', async () => {
    const result = await validateTargetUrl('http://metadata.google.internal/computeMetadata/v1/');
    expect(result.isValid).toBe(false);
    expect(result.error).toContain('metadata');
  });

  test('Rejects dangerous URI schemes (gopher://, file://, dict://)', async () => {
    const gopher = await validateTargetUrl('gopher://127.0.0.1:70/_');
    expect(gopher.isValid).toBe(false);

    const file = await validateTargetUrl('file:///etc/passwd');
    expect(file.isValid).toBe(false);
  });
});
