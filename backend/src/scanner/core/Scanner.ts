import { ScanContext, ScanOptions } from './ScanContext';
import { RequestManager } from './RequestManager';
import { HeadersScanner } from '../modules/HeadersScanner';
import { TLSScanner } from '../modules/TLSScanner';
import { CookieScanner } from '../modules/CookieScanner';
import { TechnologyScanner } from '../modules/TechnologyScanner';
import { InformationDisclosureScanner } from '../modules/InformationDisclosureScanner';
import { InjectionScanner } from '../modules/InjectionScanner';
import { AccessControlScanner } from '../modules/AccessControlScanner';
import { OWASPEngine } from '../owasp/OWASPEngine';
import { RiskCalculator } from '../scoring/RiskCalculator';
import { validateTargetUrl } from '../../security/ssrfGuardian';
import { redisStore } from '../../services/redis';

export class Scanner {
  private headersScanner = new HeadersScanner();
  private tlsScanner = new TLSScanner();
  private cookieScanner = new CookieScanner();
  private techScanner = new TechnologyScanner();
  private infoScanner = new InformationDisclosureScanner();
  private injectionScanner = new InjectionScanner();
  private accessScanner = new AccessControlScanner();
  private owaspEngine = new OWASPEngine();
  private riskCalculator = new RiskCalculator();
  private requestManager = new RequestManager();

  public async executeScan(options: ScanOptions, onProgress?: (step: string, percent: number) => void): Promise<ScanContext> {
    const context = new ScanContext(options);
    const updateProgress = async (step: string, percent: number) => {
      console.log(`[Scan ${context.scanId}] (${percent}%) - ${step}`);
      await redisStore.setex(`scan:progress:${context.scanId}`, 3600, JSON.stringify({ step, percent, timestamp: new Date() }));
      if (onProgress) onProgress(step, percent);
    };

    try {
      // Step 1: Target Validation & SSRF Check
      await updateProgress('Target validation & SSRF check', 10);
      const validation = await validateTargetUrl(context.targetUrl);
      if (!validation.isValid) {
        throw new Error(`Target Validation Failed: ${validation.error}`);
      }
      context.targetUrl = validation.normalizedUrl || context.targetUrl;

      // Check Cancellation
      if (await this.isCancelled(context.scanId)) throw new Error('Scan cancelled by user.');

      // Step 2: Establish HTTP Connection & Fetch Initial DOM/Headers
      await updateProgress('HTTP/HTTPS connection & response analysis', 25);
      const httpRes = await this.requestManager.fetchUrl(context.targetUrl);
      context.statusCode = httpRes.statusCode;
      context.rawHeaders = httpRes.headers;
      context.htmlContent = httpRes.body;

      if (await this.isCancelled(context.scanId)) throw new Error('Scan cancelled by user.');

      // Step 3: Security Headers Analysis
      await updateProgress('Security headers analysis', 40);
      await this.headersScanner.scan(context);

      // Step 4: TLS / SSL Certificate Inspection
      await updateProgress('TLS / SSL certificate analysis', 50);
      await this.tlsScanner.scan(context);

      // Step 5: Cookie Security Attributes
      await updateProgress('Cookie security attributes analysis', 60);
      await this.cookieScanner.scan(context);

      // Step 6: Technology Fingerprinting
      await updateProgress('Technology stack fingerprinting', 70);
      await this.techScanner.scan(context);

      // Step 7: Information Disclosure & Path Probes
      await updateProgress('Information disclosure & path safety checks', 80);
      await this.infoScanner.scan(context);
      await this.injectionScanner.scan(context);
      await this.accessScanner.scan(context);

      // Step 8: OWASP Alignment & Risk Calculation
      await updateProgress('OWASP Top 10 mapping & risk scoring', 90);
      this.owaspEngine.mapResults(context);
      this.riskCalculator.calculateScore(context);

      context.endTime = new Date();
      await updateProgress('Scan completed successfully', 100);

      return context;
    } catch (err: any) {
      console.error(`[Scan ${context.scanId}] Failure:`, err.message);
      await redisStore.setex(`scan:progress:${context.scanId}`, 3600, JSON.stringify({ step: `Failed: ${err.message}`, percent: -1, error: err.message }));
      throw err;
    }
  }

  private async isCancelled(scanId: string): Promise<boolean> {
    const flag = await redisStore.get(`scan:cancel:${scanId}`);
    return flag === 'true';
  }
}
