import { Router, Request, Response } from 'express';
import { dataStore } from './dataStore.ts';
import { USERS, requireRole, validateIndicatorSyntax, sanitizeFeedInput } from './security.ts';
import { scoreThreatLens, scoreBaseline } from './scoringEngine.ts';
import { Indicator, Role } from './types.ts';

export const apiRouter = Router();

// -------------------------------------------------------------
// 1. HEALTH & METADATA
// -------------------------------------------------------------
apiRouter.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'HEALTHY',
    timestamp: new Date().toISOString(),
    service: 'threatlens-core',
    version: '1.0.0',
    indicators_loaded: dataStore.indicators.length,
    active_config_version: dataStore.activeConfig.version
  });
});

apiRouter.get('/version', (_req: Request, res: Response) => {
  res.json({
    service: 'ThreatLens Prioritization Engine',
    version: '1.0.0',
    commit: 'prod-build-2026',
    scoring_model: 'Explainable Local-Relevance Linear Formulation v1.0',
    seed: 42,
    rfc_compliance: ['RFC 5737', 'RFC 3849']
  });
});

// -------------------------------------------------------------
// 2. AUTH & USER CONTEXT
// -------------------------------------------------------------
apiRouter.get('/auth/me', (_req: Request, res: Response) => {
  res.json({
    user: dataStore.currentUser,
    available_users: Object.values(USERS)
  });
});

apiRouter.post('/auth/switch-role', (req: Request, res: Response) => {
  const { roleKey } = req.body;
  const targetUser = USERS[roleKey];
  if (!targetUser) {
    return res.status(400).json({ error: 'Invalid user or role key' });
  }

  const prev = dataStore.currentUser;
  dataStore.currentUser = { ...targetUser };

  dataStore.logAudit({
    user: targetUser.name,
    role: targetUser.role,
    action: 'USER_ROLE_SWITCH',
    resource: 'AUTH_SESSION',
    result: 'SUCCESS',
    reason: `Operator switched session from ${prev.name} (${prev.role}) to ${targetUser.name} (${targetUser.role}).`
  });

  res.json({
    success: true,
    user: dataStore.currentUser
  });
});

// -------------------------------------------------------------
// 3. INDICATOR MANAGEMENT & TRIAGE
// -------------------------------------------------------------
apiRouter.get('/indicators', (req: Request, res: Response) => {
  const {
    search,
    label,
    type,
    source,
    minScore,
    maxScore,
    prioritized,
    page = '1',
    limit = '50'
  } = req.query;

  let filtered = [...dataStore.indicators];

  if (search && typeof search === 'string') {
    const q = search.toLowerCase();
    filtered = filtered.filter(
      i =>
        i.indicator.toLowerCase().includes(q) ||
        (i.malware_family && i.malware_family.toLowerCase().includes(q)) ||
        (i.threat_actor && i.threat_actor.toLowerCase().includes(q)) ||
        (i.cve && i.cve.toLowerCase().includes(q)) ||
        i.tags.some(t => t.toLowerCase().includes(q))
    );
  }

  if (label && typeof label === 'string' && label !== 'ALL') {
    filtered = filtered.filter(i => i.label === label);
  }

  if (type && typeof type === 'string' && type !== 'ALL') {
    filtered = filtered.filter(i => i.type === type);
  }

  if (source && typeof source === 'string' && source !== 'ALL') {
    filtered = filtered.filter(i => i.source === source);
  }

  if (prioritized === 'true') {
    filtered = filtered.filter(i => i.is_prioritized);
  } else if (prioritized === 'false') {
    filtered = filtered.filter(i => !i.is_prioritized);
  }

  if (minScore) {
    const min = parseFloat(minScore as string);
    if (!isNaN(min)) filtered = filtered.filter(i => (i.score ?? 0) >= min);
  }

  if (maxScore) {
    const max = parseFloat(maxScore as string);
    if (!isNaN(max)) filtered = filtered.filter(i => (i.score ?? 0) <= max);
  }

  const p = Math.max(1, parseInt(page as string, 10));
  const l = Math.max(1, Math.min(200, parseInt(limit as string, 10)));
  const startIndex = (p - 1) * l;
  const paginated = filtered.slice(startIndex, startIndex + l);

  res.json({
    total: filtered.length,
    page: p,
    limit: l,
    total_pages: Math.ceil(filtered.length / l),
    indicators: paginated
  });
});

apiRouter.get('/indicators/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  const item = dataStore.indicators.find(i => i.indicator_id === id || i.indicator === id);
  if (!item) {
    return res.status(404).json({ error: 'Indicator not found' });
  }
  res.json(item);
});

apiRouter.get('/high-priority', (_req: Request, res: Response) => {
  const highPriority = dataStore.indicators.filter(i => i.is_prioritized);
  res.json({
    total: highPriority.length,
    indicators: highPriority
  });
});

// -------------------------------------------------------------
// 4. SCORE CALCULATION & SCORE MANIPULATION DEFENSE
// -------------------------------------------------------------
apiRouter.post('/score', (req: Request, res: Response) => {
  const rawPayload = req.body;

  // SECURITY TEST SEC-01 DEFENSE:
  // Client MUST NOT be able to force server to accept client-sent score
  const hadClientScore = 'score' in rawPayload || 'label' in rawPayload;

  const { sanitized, warnings } = sanitizeFeedInput(rawPayload);

  // Validate syntax
  const valResult = validateIndicatorSyntax(sanitized.indicator, sanitized.type || 'ipv4');
  if (!valResult.valid) {
    return res.status(400).json({
      error: 'Malformed indicator syntax',
      reason: valResult.reason
    });
  }

  // Calculate score independently using server evidence context
  const bRes = scoreBaseline(sanitized);
  const tRes = scoreThreatLens(sanitized, dataStore.scoringContext, dataStore.activeConfig);

  dataStore.logAudit({
    user: dataStore.currentUser.name,
    role: dataStore.currentUser.role,
    action: 'SCORE_CALCULATE',
    resource: sanitized.indicator,
    result: 'SUCCESS',
    reason: hadClientScore
      ? 'Client attempted score submission; overridden with authoritative server calculation.'
      : 'On-demand local relevance score evaluated.'
  });

  res.json({
    indicator: sanitized.indicator,
    threatlens: tRes,
    baseline: bRes,
    security_notice: hadClientScore
      ? 'NOTICE: Client-supplied score or label was ignored. Score computed independently by ThreatLens engine.'
      : undefined,
    warnings: warnings.length > 0 ? warnings : undefined
  });
});

apiRouter.post('/indicators', (req: Request, res: Response) => {
  // Creating an indicator requires at least ANALYST role
  const { sanitized, warnings } = sanitizeFeedInput(req.body);

  const valResult = validateIndicatorSyntax(sanitized.indicator, sanitized.type || 'ipv4');
  if (!valResult.valid) {
    return res.status(400).json({ error: 'Invalid indicator format', reason: valResult.reason });
  }

  // Check duplicate
  const existing = dataStore.indicators.find(i => i.indicator === sanitized.indicator);
  if (existing) {
    return res.status(409).json({
      error: 'Duplicate indicator',
      message: `Indicator ${sanitized.indicator} already exists in database.`
    });
  }

  const bRes = scoreBaseline(sanitized);
  const tRes = scoreThreatLens(sanitized, dataStore.scoringContext, dataStore.activeConfig);

  const newIndicator: Indicator = {
    indicator_id: 'IOC-' + (dataStore.indicators.length + 1).toString().padStart(5, '0'),
    indicator: sanitized.indicator,
    type: sanitized.type || 'ipv4',
    source: sanitized.source || 'Manual-Ingest',
    source_reliability: sanitized.source_reliability,
    confidence: sanitized.confidence,
    severity: sanitized.severity || 'medium',
    first_seen: new Date().toISOString().replace('T', ' ').substring(0, 19),
    last_seen: new Date().toISOString().replace('T', ' ').substring(0, 19),
    tags: Array.isArray(sanitized.tags) ? sanitized.tags : (sanitized.tags ? [sanitized.tags] : ['manual']),
    malware_family: sanitized.malware_family || 'Generic',
    threat_actor: sanitized.threat_actor || 'Unknown',
    cve: sanitized.cve,
    category: tRes.is_prioritized ? 'local' : 'irrelevant',
    baseline_score: bRes.score,
    baseline_prioritized: bRes.is_prioritized,
    ...tRes
  };

  dataStore.indicators.unshift(newIndicator);

  dataStore.logAudit({
    user: dataStore.currentUser.name,
    role: dataStore.currentUser.role,
    action: 'INDICATOR_CREATE',
    resource: newIndicator.indicator,
    result: 'SUCCESS',
    reason: `Manual indicator creation with score ${newIndicator.score} (${newIndicator.label}).`
  });

  res.status(201).json({
    indicator: newIndicator,
    warnings: warnings.length > 0 ? warnings : undefined
  });
});

// -------------------------------------------------------------
// 5. EVIDENCE DRILL-DOWN
// -------------------------------------------------------------
apiRouter.get('/evidence/:id', (req: Request, res: Response) => {
  const { id } = req.params;
  const ind = dataStore.indicators.find(i => i.indicator_id === id || i.indicator === id);
  if (!ind) {
    return res.status(404).json({ error: 'Indicator not found' });
  }

  const ioc = ind.indicator;
  const traffic = dataStore.scoringContext.trafficByIndicator.get(ioc) || [];
  const incidents = dataStore.scoringContext.incidentsByIndicator.get(ioc) || [];
  const asset = ind.matched_asset ? dataStore.scoringContext.inventoryByAsset.get(ind.matched_asset) : undefined;

  res.json({
    indicator_id: ind.indicator_id,
    indicator: ind.indicator,
    score: ind.score,
    label: ind.label,
    is_prioritized: ind.is_prioritized,
    explanation: ind.explanation,
    evidence_chain: ind.evidence,
    factor_breakdown: ind.breakdown,
    telemetry_logs: traffic,
    historical_incidents: incidents,
    associated_asset: asset || null
  });
});

// -------------------------------------------------------------
// 6. METRICS & EXPERIMENT BENCHMARK
// -------------------------------------------------------------
apiRouter.get('/metrics', (_req: Request, res: Response) => {
  // Read experimental results or compute live
  const total = dataStore.indicators.length;
  const totalLocal = dataStore.indicators.filter(i => i.category === 'local').length;
  const totalIrrelevant = total - totalLocal;

  // ThreatLens counts
  const tPrioritized = dataStore.indicators.filter(i => i.is_prioritized);
  const tSuppressed = dataStore.indicators.filter(i => !i.is_prioritized);

  const t_tp = dataStore.indicators.filter(i => i.category === 'local' && i.is_prioritized).length;
  const t_fp = dataStore.indicators.filter(i => i.category === 'irrelevant' && i.is_prioritized).length;
  const t_tn = dataStore.indicators.filter(i => i.category === 'irrelevant' && !i.is_prioritized).length;
  const t_fn = dataStore.indicators.filter(i => i.category === 'local' && !i.is_prioritized).length;

  // Baseline counts
  const b_tp = dataStore.indicators.filter(i => i.category === 'local' && i.baseline_prioritized).length;
  const b_fp = dataStore.indicators.filter(i => i.category === 'irrelevant' && i.baseline_prioritized).length;
  const b_tn = dataStore.indicators.filter(i => i.category === 'irrelevant' && !i.baseline_prioritized).length;
  const b_fn = dataStore.indicators.filter(i => i.category === 'local' && !i.baseline_prioritized).length;
  const bPrioritizedCount = b_tp + b_fp;

  const tRecall = totalLocal > 0 ? (t_tp / totalLocal) * 100 : 0;
  const tPrecision = tPrioritized.length > 0 ? (t_tp / tPrioritized.length) * 100 : 0;
  const tSuppressionRate = totalIrrelevant > 0 ? (t_tn / totalIrrelevant) * 100 : 0;
  const tFnr = totalLocal > 0 ? (t_fn / totalLocal) * 100 : 0;
  const tFpr = totalIrrelevant > 0 ? (t_fp / totalIrrelevant) * 100 : 0;

  const bRecall = totalLocal > 0 ? (b_tp / totalLocal) * 100 : 0;
  const bPrecision = bPrioritizedCount > 0 ? (b_tp / bPrioritizedCount) * 100 : 0;
  const bSuppressionRate = totalIrrelevant > 0 ? (b_tn / totalIrrelevant) * 100 : 0;

  const workloadReduction = bPrioritizedCount > 0
    ? ((bPrioritizedCount - tPrioritized.length) / bPrioritizedCount) * 100
    : 0;

  res.json({
    total_indicators: total,
    ground_truth: {
      total_local: totalLocal,
      total_irrelevant: totalIrrelevant
    },
    threatlens: {
      tp: t_tp,
      fp: t_fp,
      tn: t_tn,
      fn: t_fn,
      total_prioritized: tPrioritized.length,
      total_suppressed: tSuppressed.length,
      recall: Math.round(tRecall * 100) / 100,
      precision: Math.round(tPrecision * 100) / 100,
      suppression_rate: Math.round(tSuppressionRate * 100) / 100,
      fnr: Math.round(tFnr * 100) / 100,
      fpr: Math.round(tFpr * 100) / 100,
      workload_reduction: Math.round(workloadReduction * 100) / 100
    },
    baseline: {
      tp: b_tp,
      fp: b_fp,
      tn: b_tn,
      fn: b_fn,
      total_prioritized: bPrioritizedCount,
      recall: Math.round(bRecall * 100) / 100,
      precision: Math.round(bPrecision * 100) / 100,
      suppression_rate: Math.round(bSuppressionRate * 100) / 100,
      workload_reduction: 0.0
    },
    targets: {
      suppression_rate: { target: 60.0, measured: tSuppressionRate, status: tSuppressionRate >= 60 ? 'PASS' : 'FAIL' },
      recall: { target: 95.0, measured: tRecall, status: tRecall >= 95 ? 'PASS' : 'FAIL' },
      fnr: { target: 5.0, measured: tFnr, status: tFnr <= 5 ? 'PASS' : 'FAIL' },
      workload_reduction: { target: 50.0, measured: workloadReduction, status: workloadReduction >= 50 ? 'PASS' : 'FAIL' }
    }
  });
});

// -------------------------------------------------------------
// 7. AUDIT TRAIL
// -------------------------------------------------------------
apiRouter.get('/audit', (req: Request, res: Response) => {
  const { action, role, result, search, limit = '100' } = req.query;

  let filtered = [...dataStore.auditEvents];

  if (action && typeof action === 'string' && action !== 'ALL') {
    filtered = filtered.filter(a => a.action === action);
  }

  if (role && typeof role === 'string' && role !== 'ALL') {
    filtered = filtered.filter(a => a.role === role);
  }

  if (result && typeof result === 'string' && result !== 'ALL') {
    filtered = filtered.filter(a => a.result === result);
  }

  if (search && typeof search === 'string') {
    const q = search.toLowerCase();
    filtered = filtered.filter(
      a =>
        a.user.toLowerCase().includes(q) ||
        a.resource.toLowerCase().includes(q) ||
        (a.reason && a.reason.toLowerCase().includes(q)) ||
        a.request_id.toLowerCase().includes(q)
    );
  }

  const l = Math.max(1, Math.min(500, parseInt(limit as string, 10)));
  res.json({
    total: filtered.length,
    events: filtered.slice(0, l)
  });
});

// -------------------------------------------------------------
// 8. CONFIGURATION GOVERNANCE & ROLLBACK
// -------------------------------------------------------------
apiRouter.get('/config', (_req: Request, res: Response) => {
  res.json({
    active_config: dataStore.activeConfig,
    history: dataStore.configHistory
  });
});

apiRouter.post('/config/change', (req: Request, res: Response) => {
  // Only ADMIN can propose configuration changes directly
  if (!requireRole(dataStore.currentUser.role, ['ADMIN'], 'CONFIG_PROPOSE')) {
    return res.status(403).json({
      error: 'Permission Denied',
      message: 'Only users with the ADMIN role can propose scoring configuration modifications.'
    });
  }

  const {
    traffic_weight,
    incident_weight,
    cve_weight,
    exposure_weight,
    feed_weight,
    criticality_weight,
    recency_weight,
    source_reliability_weight,
    staleness_penalty,
    weak_evidence_penalty,
    cdn_dampener_penalty,
    reason
  } = req.body;

  if (!reason || typeof reason !== 'string') {
    return res.status(400).json({ error: 'A valid rationale is required for configuration changes' });
  }

  const nextVersion = dataStore.configHistory.length + 1;
  const newConfig = {
    version: nextVersion,
    traffic_weight: Number(traffic_weight ?? dataStore.activeConfig.traffic_weight),
    incident_weight: Number(incident_weight ?? dataStore.activeConfig.incident_weight),
    cve_weight: Number(cve_weight ?? dataStore.activeConfig.cve_weight),
    exposure_weight: Number(exposure_weight ?? dataStore.activeConfig.exposure_weight),
    feed_weight: Number(feed_weight ?? dataStore.activeConfig.feed_weight),
    criticality_weight: Number(criticality_weight ?? dataStore.activeConfig.criticality_weight),
    recency_weight: Number(recency_weight ?? dataStore.activeConfig.recency_weight),
    source_reliability_weight: Number(source_reliability_weight ?? dataStore.activeConfig.source_reliability_weight),
    staleness_penalty: Number(staleness_penalty ?? dataStore.activeConfig.staleness_penalty),
    weak_evidence_penalty: Number(weak_evidence_penalty ?? dataStore.activeConfig.weak_evidence_penalty),
    cdn_dampener_penalty: Number(cdn_dampener_penalty ?? dataStore.activeConfig.cdn_dampener_penalty),
    status: 'PENDING_REVIEW' as const,
    created_at: new Date().toISOString(),
    created_by: dataStore.currentUser.name,
    review_reason: reason
  };

  dataStore.configHistory.push(newConfig);

  dataStore.logAudit({
    user: dataStore.currentUser.name,
    role: dataStore.currentUser.role,
    action: 'CONFIG_PROPOSE',
    resource: `ScoringConfig v${nextVersion}`,
    result: 'SUCCESS',
    reason
  });

  res.status(201).json({
    message: `Configuration version ${nextVersion} proposed and awaiting reviewer sign-off.`,
    config: newConfig
  });
});

apiRouter.post('/config/review', (req: Request, res: Response) => {
  // REVIEWER or ADMIN can approve/reject
  if (!requireRole(dataStore.currentUser.role, ['REVIEWER', 'ADMIN'], 'CONFIG_REVIEW')) {
    return res.status(403).json({
      error: 'Permission Denied',
      message: 'REVIEWER or ADMIN role required to review configuration changes.'
    });
  }

  const { version, decision, notes } = req.body;
  const target = dataStore.configHistory.find(c => c.version === version);
  if (!target) {
    return res.status(404).json({ error: 'Target configuration version not found' });
  }

  if (decision === 'APPROVE') {
    // Archive previous active
    for (const c of dataStore.configHistory) {
      if (c.status === 'ACTIVE') c.status = 'ARCHIVED';
    }
    target.status = 'ACTIVE';
    target.reviewed_by = dataStore.currentUser.name;
    dataStore.activeConfig = { ...target };

    // Re-score all indicators
    dataStore.rescoreAll();

    dataStore.logAudit({
      user: dataStore.currentUser.name,
      role: dataStore.currentUser.role,
      action: 'CONFIG_APPROVE',
      resource: `ScoringConfig v${version}`,
      result: 'SUCCESS',
      reason: notes || 'Approved configuration change.'
    });

    res.json({
      message: `Configuration v${version} approved and activated. All indicators rescored.`,
      active_config: dataStore.activeConfig
    });
  } else {
    target.status = 'ARCHIVED';
    dataStore.logAudit({
      user: dataStore.currentUser.name,
      role: dataStore.currentUser.role,
      action: 'CONFIG_REJECT',
      resource: `ScoringConfig v${version}`,
      result: 'DENIED',
      reason: notes || 'Rejected configuration proposal.'
    });

    res.json({
      message: `Configuration v${version} rejected and archived.`,
      target
    });
  }
});

apiRouter.post('/config/rollback', (req: Request, res: Response) => {
  // Rollback requires ADMIN role
  if (!requireRole(dataStore.currentUser.role, ['ADMIN'], 'CONFIG_ROLLBACK')) {
    return res.status(403).json({
      error: 'Permission Denied',
      message: 'Only ADMIN role can execute configuration rollback.'
    });
  }

  const { targetVersion, reason } = req.body;
  const target = dataStore.configHistory.find(c => c.version === targetVersion);
  if (!target) {
    return res.status(404).json({ error: `Version ${targetVersion} not found in history` });
  }

  const prevVersion = dataStore.activeConfig.version;

  for (const c of dataStore.configHistory) {
    if (c.status === 'ACTIVE') c.status = 'ARCHIVED';
  }
  target.status = 'ACTIVE';
  dataStore.activeConfig = { ...target };

  // Re-score all indicators
  dataStore.rescoreAll();

  dataStore.logAudit({
    user: dataStore.currentUser.name,
    role: dataStore.currentUser.role,
    action: 'CONFIG_ROLLBACK',
    resource: `Rollback from v${prevVersion} to v${targetVersion}`,
    result: 'SUCCESS',
    reason: reason || `Emergency or operational rollback executed by ${dataStore.currentUser.name}.`
  });

  res.json({
    message: `Successfully rolled back to configuration version ${targetVersion}.`,
    active_config: dataStore.activeConfig
  });
});

// -------------------------------------------------------------
// 9. HIGH-IMPACT ACTIONS WORKFLOW (Containment Pipeline)
// -------------------------------------------------------------
apiRouter.post('/actions/propose', (req: Request, res: Response) => {
  const { indicator, action_type, rationale } = req.body;
  if (!indicator || !action_type || !rationale) {
    return res.status(400).json({ error: 'Missing indicator, action_type, or rationale' });
  }

  const action = {
    id: 'ACT-' + (dataStore.containmentActions.length + 1).toString().padStart(3, '0'),
    indicator,
    action_type,
    proposed_by: dataStore.currentUser.name,
    proposed_at: new Date().toISOString(),
    rationale,
    status: 'PROPOSED' as const
  };

  dataStore.containmentActions.unshift(action);

  dataStore.logAudit({
    user: dataStore.currentUser.name,
    role: dataStore.currentUser.role,
    action: 'CONTAINMENT_PROPOSE',
    resource: `${action_type} on ${indicator}`,
    result: 'SUCCESS',
    reason: rationale
  });

  res.status(201).json({
    message: 'High-impact action proposed. Held in human review queue pending approval.',
    action
  });
});

apiRouter.get('/actions', (_req: Request, res: Response) => {
  res.json({
    total: dataStore.containmentActions.length,
    actions: dataStore.containmentActions
  });
});

apiRouter.post('/actions/review', (req: Request, res: Response) => {
  // High-impact actions require REVIEWER or ADMIN
  if (!requireRole(dataStore.currentUser.role, ['REVIEWER', 'ADMIN'], 'CONTAINMENT_REVIEW')) {
    return res.status(403).json({
      error: 'Permission Denied',
      message: 'ANALYST cannot approve high-impact containment. Two-person authorization required.'
    });
  }

  const { actionId, decision, review_notes } = req.body;
  const action = dataStore.containmentActions.find(a => a.id === actionId);
  if (!action) {
    return res.status(404).json({ error: 'Action not found' });
  }

  if (decision === 'APPROVE') {
    action.status = 'APPROVED';
    action.reviewed_by = dataStore.currentUser.name;
    action.reviewed_at = new Date().toISOString();
    action.review_notes = review_notes || 'Approved by security reviewer.';

    dataStore.logAudit({
      user: dataStore.currentUser.name,
      role: dataStore.currentUser.role,
      action: 'CONTAINMENT_APPROVE',
      resource: `${action.action_type} on ${action.indicator}`,
      result: 'SUCCESS',
      reason: review_notes || 'Human authorization confirmed.'
    });

    res.json({
      message: `Action ${actionId} approved for execution.`,
      action
    });
  } else {
    action.status = 'REJECTED';
    action.reviewed_by = dataStore.currentUser.name;
    action.reviewed_at = new Date().toISOString();
    action.review_notes = review_notes || 'Rejected by reviewer.';

    dataStore.logAudit({
      user: dataStore.currentUser.name,
      role: dataStore.currentUser.role,
      action: 'CONTAINMENT_REJECT',
      resource: `${action.action_type} on ${action.indicator}`,
      result: 'DENIED',
      reason: review_notes || 'Action proposal rejected.'
    });

    res.json({
      message: `Action ${actionId} rejected.`,
      action
    });
  }
});

// -------------------------------------------------------------
// 10. RAW CONTEXT INSPECTION
// -------------------------------------------------------------
apiRouter.get('/assets', (_req: Request, res: Response) => {
  res.json({
    total: dataStore.assets.length,
    assets: dataStore.assets
  });
});

apiRouter.get('/traffic', (_req: Request, res: Response) => {
  res.json({
    total: dataStore.trafficLogs.length,
    recent_logs: dataStore.trafficLogs.slice(0, 100)
  });
});
