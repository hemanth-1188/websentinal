import * as cheerio from 'cheerio';
import { ScanContext } from '../core/ScanContext';
import { EvidenceRedactor } from '../../services/evidenceRedactor';

export class TechnologyScanner {
  public async scan(context: ScanContext): Promise<void> {
    const html = context.htmlContent;
    const headers = context.rawHeaders;
    context.totalChecksExecuted += 1;

    if (!html && Object.keys(headers).length === 0) return;

    const $ = cheerio.load(html || '');

    // 1. Meta generator tag detection
    const generator = $('meta[name="generator"]').attr('content') || $('meta[name="Generator"]').attr('content');
    if (generator) {
      context.addTechnology({
        name: generator,
        category: 'CMS / Framework Generator',
        confidence: 'HIGH',
      });
    }

    // 2. Server headers fingerprinting
    const server = headers['server'];
    if (server) {
      if (server.toLowerCase().includes('nginx')) {
        context.addTechnology({ name: 'Nginx', category: 'Web Server', confidence: 'HIGH' });
      } else if (server.toLowerCase().includes('apache')) {
        context.addTechnology({ name: 'Apache', category: 'Web Server', confidence: 'HIGH' });
      } else if (server.toLowerCase().includes('cloudflare')) {
        context.addTechnology({ name: 'Cloudflare', category: 'CDN / Reverse Proxy', confidence: 'HIGH' });
      } else {
        context.addTechnology({ name: server, category: 'Web Server', confidence: 'MEDIUM' });
      }
    }

    // 3. X-Powered-By detection
    const poweredBy = headers['x-powered-by'];
    if (poweredBy) {
      if (poweredBy.toLowerCase().includes('express')) {
        context.addTechnology({ name: 'Express.js', category: 'Node.js Web Framework', confidence: 'HIGH' });
      } else if (poweredBy.toLowerCase().includes('php')) {
        context.addTechnology({ name: 'PHP', category: 'Programming Language', confidence: 'HIGH' });
      } else if (poweredBy.toLowerCase().includes('next.js')) {
        context.addTechnology({ name: 'Next.js', category: 'React Framework', confidence: 'HIGH' });
      } else {
        context.addTechnology({ name: poweredBy, category: 'Backend Engine', confidence: 'HIGH' });
      }
    }

    // 4. HTML DOM inspection for frontend frameworks
    if (html.includes('_next/') || html.includes('__NEXT_DATA__')) {
      context.addTechnology({ name: 'Next.js', category: 'Frontend Framework', confidence: 'HIGH' });
      context.addTechnology({ name: 'React', category: 'UI Library', confidence: 'HIGH' });
    } else if (html.includes('react') || $('[data-reactroot]').length > 0) {
      context.addTechnology({ name: 'React', category: 'UI Library', confidence: 'HIGH' });
    }

    if (html.includes('wp-content') || html.includes('wp-includes')) {
      context.addTechnology({ name: 'WordPress', category: 'Content Management System', confidence: 'HIGH' });
    }

    if (html.includes('jquery') || $('script[src*="jquery"]').length > 0) {
      context.addTechnology({ name: 'jQuery', category: 'JavaScript Library', confidence: 'HIGH' });
    }

    if (html.includes('bootstrap') || $('link[href*="bootstrap"]').length > 0) {
      context.addTechnology({ name: 'Bootstrap', category: 'CSS Framework', confidence: 'HIGH' });
    }

    // Add general Technology Supply Chain Finding if fingerprinting succeeded
    if (context.technologies.length > 0) {
      const techList = context.technologies.map(t => `${t.name} (${t.category})`).join(', ');
      context.addFinding({
        rule_id: 'SEC-TECH-FINGERPRINT',
        title: 'Identified Component Stack (Supply Chain Inventory)',
        description: 'Fingerprinted active web software components, client libraries, and web server runtimes for patch management review.',
        severity: 'INFORMATIONAL',
        confidence: 'HIGH',
        status: 'CONFIRMED',
        check_status: 'FINDING',
        owasp_category: 'A03',
        owasp_version: '2025',
        cwe: 'CWE-200',
        affected_url: context.targetUrl,
        evidence: EvidenceRedactor.redact(`Identified technologies: ${techList}`),
        impact: 'Publicly observable technology stacks allow attackers to target known CVE vulnerabilities affecting specific versions.',
        remediation: 'Regularly audit software dependencies using SCA tools and apply security updates promptly.',
        references: 'https://owasp.org/www-project-top-ten/2025/A03_Software_Supply_Chain_Failures/',
      });
    }
  }
}
