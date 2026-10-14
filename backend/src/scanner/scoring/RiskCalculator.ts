import { ScanContext } from '../core/ScanContext';

export interface SecurityScoreReport {
  score: number;
  riskRating: 'Excellent' | 'Good' | 'Moderate' | 'Poor' | 'Critical Risk';
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  totalDeduction: number;
}

export class RiskCalculator {
  public calculateScore(context: ScanContext): SecurityScoreReport {
    let score = 100;
    let criticalCount = 0;
    let highCount = 0;
    let mediumCount = 0;
    let lowCount = 0;
    let infoCount = 0;

    for (const finding of context.findings) {
      let baseDeduction = 0;

      switch (finding.severity) {
        case 'CRITICAL':
          baseDeduction = 25;
          criticalCount++;
          break;
        case 'HIGH':
          baseDeduction = 15;
          highCount++;
          break;
        case 'MEDIUM':
          baseDeduction = 8;
          mediumCount++;
          break;
        case 'LOW':
          baseDeduction = 3;
          lowCount++;
          break;
        case 'INFORMATIONAL':
          baseDeduction = 1;
          infoCount++;
          break;
      }

      // Confidence weighting
      let confidenceMultiplier = 1.0;
      if (finding.confidence === 'MEDIUM') confidenceMultiplier = 0.8;
      if (finding.confidence === 'LOW') confidenceMultiplier = 0.5;

      score -= baseDeduction * confidenceMultiplier;
    }

    // Ensure range [0, 100]
    score = Math.max(0, Math.min(100, Math.round(score)));
    context.securityScore = score;

    let riskRating: 'Excellent' | 'Good' | 'Moderate' | 'Poor' | 'Critical Risk' = 'Excellent';
    if (score >= 90) riskRating = 'Excellent';
    else if (score >= 75) riskRating = 'Good';
    else if (score >= 60) riskRating = 'Moderate';
    else if (score >= 40) riskRating = 'Poor';
    else riskRating = 'Critical Risk';

    return {
      score,
      riskRating,
      criticalCount,
      highCount,
      mediumCount,
      lowCount,
      infoCount,
      totalDeduction: 100 - score,
    };
  }
}
