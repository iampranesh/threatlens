import fs from 'fs';
import path from 'path';
import {
  Indicator,
  Asset,
  TrafficObservation,
  HistoricalIncident,
  ScoringConfig,
  AuditEvent,
  ContainmentAction,
  User,
  Role
} from './types.ts';
import { scoreBaseline, scoreThreatLens, ScoringContext } from './scoringEngine.ts';

export class DataStore {
  public assets: Asset[] = [];
  public indicators: Indicator[] = [];
  public trafficLogs: TrafficObservation[] = [];
  public historicalIncidents: HistoricalIncident[] = [];
  public auditEvents: AuditEvent[] = [];
  public containmentActions: ContainmentAction[] = [];
  public configHistory: ScoringConfig[] = [];
  public activeConfig: ScoringConfig;

  public currentUser: User = {
    id: 'USR-01',
    name: 'Sarah Chen',
    email: 'sarah.chen@threatlens.corp',
    role: 'ANALYST',
    avatar: 'SC'
  };

  public scoringContext!: ScoringContext;

  constructor() {
    this.activeConfig = {
      version: 1,
      traffic_weight: 30.0,
      incident_weight: 25.0,
      cve_weight: 20.0,
      exposure_weight: 15.0,
      feed_weight: 10.0,
      criticality_weight: 10.0,
      recency_weight: 10.0,
      source_reliability_weight: 5.0,
      staleness_penalty: 15.0,
      weak_evidence_penalty: 20.0,
      cdn_dampener_penalty: 25.0,
      status: 'ACTIVE',
      created_at: '2026-10-08T00:00:00Z',
      created_by: 'system_bootstrap',
      review_reason: 'Initial baseline configuration certified for SOC operations.'
    };
    this.configHistory.push({ ...this.activeConfig });
    this.initializeData();
  }

  private initializeData() {
    const jsonPath = path.resolve(process.cwd(), 'data/processed/pilot_dataset.json');
    if (fs.existsSync(jsonPath)) {
      try {
        const raw = fs.readFileSync(jsonPath, 'utf-8');
        const data = JSON.parse(raw);
        this.assets = data.assets || [];
        this.trafficLogs = data.traffic_logs || [];
        this.historicalIncidents = data.historical_incidents || [];
        const rawIndicators = data.indicators || [];

        this.buildContext();

        // Score all indicators on startup
        this.indicators = rawIndicators.map((rawInd: any) => {
          const bRes = scoreBaseline(rawInd);
          const tRes = scoreThreatLens(rawInd, this.scoringContext, this.activeConfig);
          return {
            ...rawInd,
            tags: typeof rawInd.tags === 'string' ? rawInd.tags.split(';') : (rawInd.tags || []),
            baseline_score: bRes.score,
            baseline_prioritized: bRes.is_prioritized,
            ...tRes
          };
        });

        // Seed initial sample containment action
        const topIndicator = this.indicators.find(i => i.score && i.score >= 80);
        if (topIndicator) {
          this.containmentActions.push({
            id: 'ACT-001',
            indicator: topIndicator.indicator,
            action_type: 'BLOCK_FIREWALL',
            proposed_by: 'Sarah Chen (Analyst)',
            proposed_at: new Date(Date.now() - 3600000).toISOString(),
            rationale: 'Active C2 beaconing detected against perimeter portal with confirmed malicious history.',
            status: 'PROPOSED'
          });
        }

        // Seed initial audit log
        this.logAudit({
          user: 'SYSTEM',
          role: 'ADMIN',
          action: 'SYSTEM_BOOTSTRAP',
          resource: 'ThreatLens DataStore',
          result: 'SUCCESS',
          reason: `Successfully loaded ${this.indicators.length} indicators, ${this.assets.length} assets, ${this.trafficLogs.length} telemetry logs.`
        });

      } catch (err) {
        console.error('Failed to parse pilot_dataset.json:', err);
      }
    }
  }

  public buildContext() {
    const inventoryByAsset = new Map<string, Asset>();
    const orgCves = new Map<string, Asset>();
    for (const a of this.assets) {
      inventoryByAsset.set(a.asset_id, a);
      if (Array.isArray(a.cves)) {
        for (const c of a.cves) {
          if (c) orgCves.set(c, a);
        }
      }
    }

    const trafficByIndicator = new Map<string, TrafficObservation[]>();
    for (const t of this.trafficLogs) {
      const arr = trafficByIndicator.get(t.indicator) || [];
      arr.push(t);
      trafficByIndicator.set(t.indicator, arr);
    }

    const incidentsByIndicator = new Map<string, HistoricalIncident[]>();
    for (const inc of this.historicalIncidents) {
      const arr = incidentsByIndicator.get(inc.indicator) || [];
      arr.push(inc);
      incidentsByIndicator.set(inc.indicator, arr);
    }

    this.scoringContext = {
      inventory: this.assets,
      inventoryByAsset,
      trafficByIndicator,
      incidentsByIndicator,
      orgCves
    };
  }

  public rescoreAll() {
    this.buildContext();
    this.indicators = this.indicators.map(ind => {
      const bRes = scoreBaseline(ind);
      const tRes = scoreThreatLens(ind, this.scoringContext, this.activeConfig);
      return {
        ...ind,
        baseline_score: bRes.score,
        baseline_prioritized: bRes.is_prioritized,
        ...tRes
      };
    });
  }

  public logAudit(params: {
    user: string;
    role: Role;
    action: string;
    resource: string;
    result: 'SUCCESS' | 'DENIED' | 'FAILED';
    reason?: string;
    details?: Record<string, any>;
  }): AuditEvent {
    // Generate UUIDv4
    const reqId = 'req-' + Math.random().toString(36).substring(2, 10) + '-' + Date.now().toString(36);
    const event: AuditEvent = {
      id: 'AUD-' + (this.auditEvents.length + 1).toString().padStart(5, '0'),
      timestamp: new Date().toISOString(),
      request_id: reqId,
      user: params.user,
      role: params.role,
      action: params.action,
      resource: params.resource,
      result: params.result,
      reason: params.reason,
      details: params.details
    };
    this.auditEvents.unshift(event);
    return event;
  }
}

export const dataStore = new DataStore();
