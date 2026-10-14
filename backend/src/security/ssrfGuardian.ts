import dns from 'dns/promises';
import { URL } from 'url';

export interface ValidationResult {
  isValid: boolean;
  resolvedIp?: string;
  normalizedUrl?: string;
  error?: string;
}

/**
 * Checks if an IPv4 address is in a private, loopback, link-local, multicast, or reserved CIDR.
 */
function isPrivateOrReservedIPv4(ip: string): boolean {
  const parts = ip.split('.').map(p => parseInt(p, 10));
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) {
    return true; // Malformed is treated as unsafe
  }

  const [a, b, c, d] = parts;

  // 0.0.0.0/8 (Current network)
  if (a === 0) return true;

  // 10.0.0.0/8 (Private)
  if (a === 10) return true;

  // 100.64.0.0/10 (Carrier-Grade NAT)
  if (a === 100 && b >= 64 && b <= 127) return true;

  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;

  // 169.254.0.0/16 (Link-Local & Cloud Metadata, e.g. 169.254.169.254)
  if (a === 169 && b === 254) return true;

  // 172.16.0.0/12 (Private)
  if (a === 172 && b >= 16 && b <= 31) return true;

  // 192.0.0.0/24 (IETF Assignments) & 192.0.2.0/24 (TEST-NET-1)
  if (a === 192 && b === 0) return true;

  // 192.168.0.0/16 (Private)
  if (a === 192 && b === 168) return true;

  // 198.18.0.0/15 (Benchmarking) & 198.51.100.0/24 (TEST-NET-2)
  if (a === 198 && (b === 18 || b === 19 || b === 51)) return true;

  // 203.0.113.0/24 (TEST-NET-3)
  if (a === 203 && b === 0 && c === 113) return true;

  // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
  if (a >= 224) return true;

  return false;
}

/**
 * Checks if an IPv6 address is in a private, loopback, link-local, multicast, or reserved range.
 */
function isPrivateOrReservedIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase();

  // Loopback (::1) and Unspecified (::)
  if (normalized === '::1' || normalized === '::') return true;

  // IPv4-mapped IPv6 (::ffff:127.0.0.1)
  if (normalized.startsWith('::ffff:')) {
    const ipv4Part = normalized.replace('::ffff:', '');
    return isPrivateOrReservedIPv4(ipv4Part);
  }

  // Link-Local (fe80::/10)
  if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) {
    return true;
  }

  // Unique Local (fc00::/7 -> fc00:: and fd00::)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) {
    return true;
  }

  // Multicast (ff00::/8)
  if (normalized.startsWith('ff')) {
    return true;
  }

  return false;
}

export function isRestrictedIp(ip: string): boolean {
  if (ip.includes(':')) {
    return isPrivateOrReservedIPv6(ip);
  }
  return isPrivateOrReservedIPv4(ip);
}

/**
 * Validates a target URL against SSRF vulnerabilities, protocol scheme restrictions,
 * and internal / cloud metadata destination blocks.
 */
export async function validateTargetUrl(rawUrl: string): Promise<ValidationResult> {
  try {
    if (!rawUrl || typeof rawUrl !== 'string') {
      return { isValid: false, error: 'Target URL is required.' };
    }

    let formattedUrl = rawUrl.trim();
    if (!formattedUrl.includes('://')) {
      formattedUrl = 'https://' + formattedUrl;
    }

    const parsedUrl = new URL(formattedUrl);

    // 1. Strict Protocol Scheme Allowlist (http: and https: only)
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return { isValid: false, error: 'Only HTTP and HTTPS protocols are allowed.' };
    }

    const hostname = parsedUrl.hostname.toLowerCase();

    // 2. Block well-known cloud metadata hostnames directly
    if (
      hostname === 'metadata.google.internal' ||
      hostname === '169.254.169.254' ||
      hostname === 'instance-data'
    ) {
      return { isValid: false, error: 'Scanning cloud metadata services is strictly prohibited.' };
    }

    // Special Exception for controlled local demo target container during local testing
    const allowDemoTarget = process.env.ALLOW_LOCAL_DEMO_TARGET === 'true';

    if (allowDemoTarget && (hostname === 'demo-target' || hostname === 'localhost' || hostname === '127.0.0.1')) {
      if (parsedUrl.port === '8080' || hostname === 'demo-target') {
        return {
          isValid: true,
          resolvedIp: '127.0.0.1',
          normalizedUrl: parsedUrl.toString(),
        };
      }
    }

    // 3. Block direct localhost / loopback names
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '0.0.0.0' || hostname === '::1' || hostname === '[::1]') {
      return { isValid: false, error: 'Scanning localhost or loopback addresses is prohibited for SSRF protection.' };
    }

    // Check if hostname is directly an IP literal
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
      if (isPrivateOrReservedIPv4(hostname)) {
        return { isValid: false, error: `Direct IP ${hostname} is in a restricted internal IP network range.` };
      }
      return {
        isValid: true,
        resolvedIp: hostname,
        normalizedUrl: parsedUrl.toString(),
      };
    }

    // 4. Resolve DNS to IPv4 and IPv6 addresses
    let addresses: string[] = [];
    try {
      const ipv4 = await dns.resolve4(hostname);
      addresses.push(...ipv4);
    } catch (e) {
      // Ignore if no IPv4
    }

    try {
      const ipv6 = await dns.resolve6(hostname);
      addresses.push(...ipv6);
    } catch (e) {
      // Ignore if no IPv6
    }

    if (addresses.length === 0) {
      return { isValid: false, error: `Unable to resolve DNS for hostname: ${hostname}` };
    }

    // 5. Validate all resolved IPs against SSRF blocklist (Protection against DNS Rebinding & Multi-A Records)
    for (const ip of addresses) {
      if (isRestrictedIp(ip)) {
        return {
          isValid: false,
          error: `Target host resolved to restricted internal IP (${ip}). Scanning internal networks is strictly prohibited.`,
        };
      }
    }

    return {
      isValid: true,
      resolvedIp: addresses[0],
      normalizedUrl: parsedUrl.toString(),
    };
  } catch (err: any) {
    return {
      isValid: false,
      error: `Invalid URL format: ${err.message}`,
    };
  }
}
