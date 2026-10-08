export type Role = 'ANALYST' | 'REVIEWER' | 'ADMIN';

export interface User {
  id: string;
  name: string;
  email: string;
  role: Role;
  avatar: string;
}

export type IndicatorType = 'ipv4' | 'ipv6' | 'domain' | 'url' | 'sha256';
export type IndicatorSeverity = 'low' | 'medium' | 'high' | 'critical';
export type ClassificationLabel = 'IRRELEVANT' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface Indicator {
  indicator_id: string;
  indicator: string;
  type: IndicatorType;
  source: string;
  source_reliability: number;
  confidence: number;
  severity: IndicatorSeverity;
  first_seen: string;
  last_seen: string;
  tags: string[];
  malware_family?: string;
  threat_actor?: string;
  cve?: string;
  category: 'local' | 'irrelevant';
  
  // Computed ThreatLens fields
  score?: number;
  label?: ClassificationLabel;
  is_prioritized?: boolean;
  evidence?: string[];
  breakdown?: Record<string, number>;
  explanation?: string;
  matched_asset?: string;

  // Baseline fields
  baseline_score?: number;
  baseline_prioritized?: boolean;
}

export interface Asset {
  asset_id: string;
  hostname: string;
  application: string;
  vendor: string;
  version: string;
  operating_system: string;
  internet_exposed: boolean;
  criticality: 'low' | 'medium' | 'high' | 'critical';
  cves: string[];
  owner: string;
  environment: 'production' | 'staging' | 'internal' | 'workstation';
}

export interface TrafficObservation {
  traffic_id: string;
  timestamp: string;
  indicator: string;
  asset_id: string;
  source_ip: string;
  destination_ip: string;
  domain?: string;
  port: number;
  protocol: string;
  bytes: number;
  direction: 'inbound' | 'outbound' | 'internal';
  action: 'allowed' | 'blocked';
  frequency: number;
}

export interface HistoricalIncident {
  incident_id: string;
  indicator: string;
  date: string;
  affected_asset: string;
  incident_type: string;
  severity: string;
  confirmed_malicious: boolean;
  resolution: string;
  business_impact: string;
}

export interface ScoringConfig {
  version: number;
  traffic_weight: number;
  incident_weight: number;
  cve_weight: number;
  exposure_weight: number;
  feed_weight: number;
  criticality_weight: number;
  recency_weight: number;
  source_reliability_weight: number;
  staleness_penalty: number;
  weak_evidence_penalty: number;
  cdn_dampener_penalty: number;
  status: 'ACTIVE' | 'ARCHIVED' | 'PENDING_REVIEW';
  created_at: string;
  created_by: string;
  reviewed_by?: string;
  review_reason?: string;
}

export interface AuditEvent {
  id: string;
  timestamp: string;
  request_id: string;
  user: string;
  role: Role;
  action: string;
  resource: string;
  result: 'SUCCESS' | 'DENIED' | 'FAILED';
  reason?: string;
  details?: Record<string, any>;
}

export interface ContainmentAction {
  id: string;
  indicator: string;
  action_type: 'BLOCK_FIREWALL' | 'ISOLATE_HOST' | 'SINKHOLE_DNS' | 'REVOKE_CREDENTIALS';
  proposed_by: string;
  proposed_at: string;
  rationale: string;
  status: 'PROPOSED' | 'APPROVED' | 'REJECTED' | 'EXECUTED';
  reviewed_by?: string;
  reviewed_at?: string;
  review_notes?: string;
}
