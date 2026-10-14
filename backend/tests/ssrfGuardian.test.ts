import { validateTargetUrl } from '../src/security/ssrfGuardian';

describe('SSRF Guardian Target Validator Tests', () => {
  test('Blocks loopback IP addresses (127.0.0.1)', async () => {
    const result = await validateTargetUrl('http://127.0.0.1/admin');
    expect(result.isValid).toBe(false);
    expect(result.error).toContain('prohibited');
  });

  test('Blocks private IPv4 network range (10.0.0.1)', async () => {
    const result = await validateTargetUrl('http://10.0.0.1:8080');
    expect(result.isValid).toBe(false);
    expect(result.error).toContain('restricted internal IP');
  });

  test('Blocks AWS / Cloud Metadata endpoint (169.254.169.254)', async () => {
    const result = await validateTargetUrl('http://169.254.169.254/latest/meta-data/');
    expect(result.isValid).toBe(false);
  });

  test('Rejects invalid protocol schemes (ftp://, file://)', async () => {
    const result = await validateTargetUrl('ftp://example.com');
    expect(result.isValid).toBe(false);
    expect(result.error).toContain('Only HTTP and HTTPS');
  });
});
