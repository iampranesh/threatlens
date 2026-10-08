import { Indicator, Asset, TrafficObservation, HistoricalIncident, ScoringConfig, ClassificationLabel } from './types.ts';

const CDN_IPS = new Set([
  '104.16.124.96', '104.21.45.12', '151.101.65.140',
  '13.224.160.10', '8.8.8.8', '1.1.1.1'
]);

export interface ScoringContext {
  inventory: Asset[];
  inventoryByAsset: Map<string, Asset>;
  trafficByIndicator: Map<string, TrafficObservation[]>;
  incidentsByIndicator: Map<string, HistoricalIncident[]>;
  orgCves: Map<string, Asset>;
}

export function scoreBaseline(indicator: Partial<Indicator>): {
  score: number;
  is_prioritized: boolean;
  classification: string;
} {
  const confidence = Number(indicator.confidence ?? 50);
  const severity = (indicator.severity ?? 'medium').toLowerCase();
  const reliability = Number(indicator.source_reliability ?? 0.8);

  const sevWeights: Record<string, number> = {
    critical: 1.0,
    high: 0.85,
    medium: 0.55,
    low: 0.25
  };
  const sevW = sevWeights[severity] ?? 0.5;

  const raw = (confidence * 0.7) + (sevW * 100 * 0.3);
  const finalScore = Math.min(100, Math.max(0, raw * (0.8 + 0.2 * reliability)));
  const isPrioritized = finalScore >= 60.0;

  return {
    score: Math.round(finalScore * 10) / 10,
    is_prioritized: isPrioritized,
    classification: finalScore >= 80 ? 'HIGH' : (isPrioritized ? 'PRIORITIZED' : 'SUPPRESSED')
  };
}

export function scoreThreatLens(
  indicator: Partial<Indicator>,
  context: ScoringContext,
  config: ScoringConfig
): {
  score: number;
  label: ClassificationLabel;
  is_prioritized: boolean;
  evidence: string[];
  breakdown: Record<string, number>;
  explanation: string;
  matched_asset: string;
} {
  const ioc = indicator.indicator || '';
  const trafficLogs = context.trafficByIndicator.get(ioc) || [];
  const incidents = context.incidentsByIndicator.get(ioc) || [];
  const cve = indicator.cve ? indicator.cve.trim() : '';
  const cveMatchAsset = cve ? context.orgCves.get(cve) : undefined;

  const evidence: string[] = [];
  const breakdown: Record<string, number> = {};

  // 1. Traffic Telemetry Factor
  let trafficScore = 0.0;
  if (trafficLogs.length > 0) {
    const totalEvents = trafficLogs.reduce((sum, t) => sum + (t.frequency || 1), 0);
    const hasAllowed = trafficLogs.some(t => t.action === 'allowed');
    trafficScore = Math.min(config.traffic_weight, 12.0 + Math.log(totalEvents + 1) * 5.0);
    if (hasAllowed) {
      trafficScore = Math.min(config.traffic_weight, trafficScore + 6.0);
    }
    evidence.push(
      `Observed in network telemetry ${totalEvents} times across ${trafficLogs.length} session logs (Allowed traffic: ${hasAllowed ? 'YES' : 'NO'}).`
    );
  }
  breakdown.traffic = Math.round(trafficScore * 100) / 100;

  // 2. Historical Incident Factor
  let incidentScore = 0.0;
  if (incidents.length > 0) {
    const confirmedCount = incidents.filter(inc => inc.confirmed_malicious).length;
    incidentScore = Math.min(config.incident_weight, 15.0 + confirmedCount * 5.0);
    const incIds = incidents.map(inc => inc.incident_id).join(', ');
    evidence.push(`Linked to confirmed historical incident(s): ${incIds}.`);
  }
  breakdown.incident = Math.round(incidentScore * 100) / 100;

  // 3. Software / CVE Inventory Match
  let cveScore = 0.0;
  if (cveMatchAsset) {
    const isExposed = cveMatchAsset.internet_exposed;
    cveScore = isExposed ? config.cve_weight : config.cve_weight * 0.65;
    evidence.push(
      `Associated CVE (${cve}) matches active internal asset ${cveMatchAsset.asset_id} running ${cveMatchAsset.application} v${cveMatchAsset.version} (Internet Exposed: ${isExposed ? 'YES' : 'NO'}).`
    );
  }
  breakdown.software_cve = Math.round(cveScore * 100) / 100;

  // 4. Organizational Asset Exposure
  let exposureScore = 0.0;
  let targetAsset: Asset | undefined = undefined;
  if (trafficLogs.length > 0) {
    const assetId = trafficLogs[0].asset_id;
    targetAsset = context.inventoryByAsset.get(assetId);
  } else if (cveMatchAsset) {
    targetAsset = cveMatchAsset;
  }

  if (targetAsset && targetAsset.internet_exposed) {
    exposureScore = config.exposure_weight;
    evidence.push(
      `Direct connection to perimeter/internet-facing asset: ${targetAsset.asset_id} (${targetAsset.hostname}).`
    );
  } else if (targetAsset) {
    exposureScore = config.exposure_weight * 0.45;
    evidence.push(`Connection to internal protected asset: ${targetAsset.asset_id}.`);
  }
  breakdown.exposure = Math.round(exposureScore * 100) / 100;

  // 5. Asset Criticality
  let criticalityScore = 0.0;
  if (targetAsset) {
    const crit = targetAsset.criticality || 'low';
    const critMap: Record<string, number> = { critical: 1.0, high: 0.75, medium: 0.45, low: 0.20 };
    criticalityScore = config.criticality_weight * (critMap[crit] || 0.2);
    evidence.push(`Target asset criticality is rated '${crit.toUpperCase()}'.`);
  }
  breakdown.asset_criticality = Math.round(criticalityScore * 100) / 100;

  // 6. External Feed Base Contribution
  const feedConf = typeof indicator.confidence === 'number' ? indicator.confidence : 50;
  const feedSev = (indicator.severity || 'medium').toLowerCase();
  const sevMultMap: Record<string, number> = { critical: 1.0, high: 0.8, medium: 0.5, low: 0.2 };
  const sevMult = sevMultMap[feedSev] || 0.5;
  const feedScore = (feedConf / 100.0) * config.feed_weight * sevMult;
  breakdown.feed_reputation = Math.round(feedScore * 100) / 100;

  // 7. Temporal Recency
  let recencyScore = 0.0;
  let daysDiff = 10.0;
  try {
    const lastSeenStr = indicator.last_seen || '2026-10-01 00:00:00';
    const lastSeenDate = new Date(lastSeenStr.replace(' ', 'T'));
    const benchmarkBase = new Date('2026-10-08T12:00:00Z');
    daysDiff = Math.max(0, (benchmarkBase.getTime() - lastSeenDate.getTime()) / (1000 * 60 * 60 * 24));
    if (daysDiff <= 1.0) {
      recencyScore = config.recency_weight;
    } else if (daysDiff <= 7.0) {
      recencyScore = config.recency_weight * 0.75;
    } else if (daysDiff <= 30.0) {
      recencyScore = config.recency_weight * 0.40;
    }
  } catch {
    daysDiff = 10.0;
  }
  breakdown.recency = Math.round(recencyScore * 100) / 100;

  // 8. Source Reliability
  const sourceRel = typeof indicator.source_reliability === 'number' ? indicator.source_reliability : 0.8;
  const sourceScore = config.source_reliability_weight * sourceRel;
  breakdown.source_reliability = Math.round(sourceScore * 100) / 100;

  // --- PENALTIES ---
  let penalties = 0.0;

  // A. Staleness Penalty
  let stalenessApplied = false;
  if (daysDiff > 90 && trafficLogs.length === 0) {
    penalties += config.staleness_penalty;
    stalenessApplied = true;
    evidence.push(
      `Staleness Penalty applied (-${config.staleness_penalty} pts): Inactive for ${Math.floor(daysDiff)} days with zero local observations.`
    );
  }
  breakdown.staleness_penalty = stalenessApplied ? -config.staleness_penalty : 0.0;

  // B. Weak Local Evidence Penalty
  let weakEvidenceApplied = false;
  const hasLocalSignals = trafficLogs.length > 0 || incidents.length > 0 || Boolean(cveMatchAsset);
  if (!hasLocalSignals) {
    penalties += config.weak_evidence_penalty;
    weakEvidenceApplied = true;
    evidence.push(
      `Weak Local Evidence Penalty applied (-${config.weak_evidence_penalty} pts): Zero organizational presence detected.`
    );
  }
  breakdown.weak_evidence_penalty = weakEvidenceApplied ? -config.weak_evidence_penalty : 0.0;

  // C. Shared CDN / Public Resolver Dampener
  let cdnApplied = false;
  if (CDN_IPS.has(ioc)) {
    penalties += config.cdn_dampener_penalty;
    cdnApplied = true;
    evidence.push(
      `Shared Cloud / CDN Infrastructure dampener applied (-${config.cdn_dampener_penalty} pts): Multi-tenant address (${ioc}).`
    );
  }
  breakdown.cdn_penalty = cdnApplied ? -config.cdn_dampener_penalty : 0.0;

  // Compute Total
  const rawTotal = (
    trafficScore +
    incidentScore +
    cveScore +
    exposureScore +
    criticalityScore +
    feedScore +
    recencyScore +
    sourceScore -
    penalties
  );
  const finalScore = Math.min(100.0, Math.max(0.0, rawTotal));

  // Classification
  let label: ClassificationLabel;
  if (finalScore >= 80.0) {
    label = 'CRITICAL';
  } else if (finalScore >= 60.0) {
    label = 'HIGH';
  } else if (finalScore >= 40.0) {
    label = 'MEDIUM';
  } else if (finalScore >= 20.0) {
    label = 'LOW';
  } else {
    label = 'IRRELEVANT';
  }

  const isPrioritized = finalScore >= 60.0;

  // High-Priority Evidence Requirement
  if (isPrioritized && evidence.length === 0) {
    evidence.push('INSUFFICIENT LOCAL EVIDENCE: Flagged by raw score but lacks verified telemetry verification.');
  }

  const roundedScore = Math.round(finalScore * 10) / 10;
  const explanation = `Assigned score ${roundedScore} (${label}). ${
    isPrioritized
      ? 'Direct local organizational exposure and active telemetry corroborate this threat.'
      : 'Suppressed due to absence of organizational vulnerability, traffic telemetry, or asset correlation.'
  }`;

  return {
    score: roundedScore,
    label,
    is_prioritized: isPrioritized,
    evidence,
    breakdown,
    explanation,
    matched_asset: targetAsset ? targetAsset.asset_id : 'NONE'
  };
}
