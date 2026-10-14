import http from 'http';
import https from 'https';
import { URL } from 'url';
import { validateTargetUrl } from '../../security/ssrfGuardian';

export interface HttpResponse {
  statusCode: number;
  headers: Record<string, string>;
  rawHeaders: string[];
  rawCookies: string[];
  body: string;
  url: string;
  redirectChain: string[];
  durationMs: number;
}

export class RequestManager {
  private userAgent = 'WebShield-Security-Assessment/1.0 (+https://webshield.io; Defensive Vulnerability Assessment)';
  private timeoutMs = parseInt(process.env.REQUEST_TIMEOUT || '10000', 10);
  private maxRedirects = parseInt(process.env.MAX_REDIRECTS || '5', 10);

  /**
   * Fetches an authorized URL with strict SSRF validation for EVERY redirect destination.
   */
  public async fetchUrl(
    targetUrl: string,
    options: { method?: string; headers?: Record<string, string>; maxBodyBytes?: number } = {}
  ): Promise<HttpResponse> {
    let currentUrl = targetUrl;
    let redirectsFollowed = 0;
    const redirectChain: string[] = [currentUrl];
    const startTime = Date.now();

    while (redirectsFollowed <= this.maxRedirects) {
      // 1. Enforce SSRF validation on target (including initial and every redirect hop)
      const validation = await validateTargetUrl(currentUrl);
      if (!validation.isValid) {
        throw new Error(`SSRF Protection Blocked Request to ${currentUrl}: ${validation.error}`);
      }

      const response = await this.executeSingleRequest(currentUrl, options);

      // 2. Handle HTTP Redirects (301, 302, 303, 307, 308)
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers['location']) {
        redirectsFollowed++;
        if (redirectsFollowed > this.maxRedirects) {
          throw new Error(`Maximum HTTP redirects (${this.maxRedirects}) exceeded for target.`);
        }

        const locationHeader = response.headers['location'];
        const redirectTarget = new URL(locationHeader, currentUrl).toString();

        // Check if redirect attempts to switch to unsafe protocol (e.g. gopher://, file://, ftp://)
        if (!redirectTarget.startsWith('http://') && !redirectTarget.startsWith('https://')) {
          throw new Error(`Insecure redirect scheme rejected: ${redirectTarget}`);
        }

        redirectChain.push(redirectTarget);
        currentUrl = redirectTarget;
        continue;
      }

      response.redirectChain = redirectChain;
      response.durationMs = Date.now() - startTime;
      return response;
    }

    throw new Error('HTTP Request failed due to redirect loop.');
  }

  private executeSingleRequest(
    targetUrl: string,
    options: { method?: string; headers?: Record<string, string>; maxBodyBytes?: number }
  ): Promise<HttpResponse> {
    return new Promise((resolve, reject) => {
      const parsedUrl = new URL(targetUrl);
      const isHttps = parsedUrl.protocol === 'https:';
      const client = isHttps ? https : http;

      // Method safety restriction
      const method = (options.method || 'GET').toUpperCase();
      const allowedMethods = ['GET', 'HEAD', 'POST'];
      if (!allowedMethods.includes(method)) {
        return reject(new Error(`HTTP method ${method} not permitted for defensive assessment.`));
      }

      const requestHeaders = {
        'User-Agent': this.userAgent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        ...options.headers,
      };

      const reqOptions = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method,
        headers: requestHeaders,
        rejectUnauthorized: false, // Allow analyzing TLS state without crashing on self-signed certs
        timeout: this.timeoutMs,
      };

      const maxBytes = options.maxBodyBytes || 5 * 1024 * 1024; // Default max 5MB
      const startTime = Date.now();

      const req = client.request(reqOptions, (res) => {
        const headers: Record<string, string> = {};
        const rawCookies: string[] = [];

        for (const [key, value] of Object.entries(res.headers)) {
          if (value) {
            headers[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : value;
            if (key.toLowerCase() === 'set-cookie') {
              if (Array.isArray(value)) rawCookies.push(...value);
              else rawCookies.push(value);
            }
          }
        }

        let data = '';
        res.setEncoding('utf8');

        res.on('data', (chunk) => {
          data += chunk;
          if (Buffer.byteLength(data, 'utf8') > maxBytes) {
            req.destroy();
            resolve({
              statusCode: res.statusCode || 200,
              headers,
              rawHeaders: res.rawHeaders,
              rawCookies,
              body: data,
              url: targetUrl,
              redirectChain: [],
              durationMs: Date.now() - startTime,
            });
          }
        });

        res.on('end', () => {
          resolve({
            statusCode: res.statusCode || 200,
            headers,
            rawHeaders: res.rawHeaders,
            rawCookies,
            body: data,
            url: targetUrl,
            redirectChain: [],
            durationMs: Date.now() - startTime,
          });
        });
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Request timed out after ${this.timeoutMs}ms to ${parsedUrl.hostname}`));
      });

      req.on('error', (err) => {
        reject(err);
      });

      req.end();
    });
  }
}
