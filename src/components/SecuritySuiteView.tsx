import React from 'react';
import {
  Lock,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Play,
  RotateCcw,
  CheckCircle2,
  XCircle,
  Terminal
} from 'lucide-react';
import { User } from '../server/types.ts';

interface SecuritySuiteViewProps {
  currentUser: User;
  onRefreshAll: () => void;
}

export const SecuritySuiteView: React.FC<SecuritySuiteViewProps> = ({
  currentUser,
  onRefreshAll
}) => {
  const [runningTest, setRunningTest] = React.useState<string | null>(null);
  const [testResults, setTestResults] = React.useState<Record<string, any>>({});

  const scenarios = [
    {
      id: 'SEC-01',
      title: 'Score Manipulation Protection Attack',
      category: 'Security Defense',
      description: 'Client attempts to submit a forged score of 100.0 ("CRITICAL") for an untargeted commodity IP.',
      payload: {
        indicator: '192.0.2.99',
        type: 'ipv4',
        score: 100.0,
        label: 'CRITICAL',
        confidence: 85,
        severity: 'high'
      },
      endpoint: '/api/score',
      method: 'POST',
      validator: (res: any) => res.threatlens?.score < 40 && res.security_notice !== undefined,
      expected: 'Server completely ignores client-supplied score; computes true local evidence score (<30.0).'
    },
    {
      id: 'SEC-02',
      title: 'RBAC Privilege Escalation Attack',
      category: 'Security Defense',
      description: 'Operator attempts to modify active scoring configuration weights without ADMIN permissions.',
      payload: {
        traffic_weight: 45,
        reason: 'Malicious unauthorized configuration tampering'
      },
      endpoint: '/api/config/change',
      method: 'POST',
      validator: (res: any, status: number) => {
        if (currentUser.role === 'ADMIN') return status === 201;
        return status === 403;
      },
      expected: currentUser.role === 'ADMIN'
        ? 'Admin role permitted to propose change.'
        : 'HTTP 403 Forbidden. Only ADMIN role can propose scoring changes.'
    },
    {
      id: 'SEC-03',
      title: 'Threat Feed Poisoning & Bounds Attack',
      category: 'Security Defense',
      description: 'Adversary injects poisoned indicator with confidence=999999 and XSS payload in CVE field.',
      payload: {
        indicator: '192.0.2.111',
        type: 'ipv4',
        confidence: 999999,
        source_reliability: 5.0,
        cve: "<script>alert('xss')</script>"
      },
      endpoint: '/api/score',
      method: 'POST',
      validator: (res: any) => res.threatlens?.score < 40 && res.warnings?.length > 0,
      expected: 'Confidence clipped to [0, 100], reliability bounded, XSS stripped, commodity threat suppressed.'
    },
    {
      id: 'SEC-04',
      title: 'Two-Person Containment Action Bypass',
      category: 'Security Defense',
      description: 'Analyst attempts to approve firewall containment action without Reviewer authorization.',
      payload: {
        actionId: 'ACT-001',
        decision: 'APPROVE',
        review_notes: 'Unauthorized approval attempt'
      },
      endpoint: '/api/actions/review',
      method: 'POST',
      validator: (res: any, status: number) => {
        if (currentUser.role === 'ANALYST') return status === 403;
        return status === 200 || status === 404;
      },
      expected: currentUser.role === 'ANALYST'
        ? 'HTTP 403 Forbidden. Analyst blocked; Reviewer or Admin required.'
        : 'Reviewer/Admin authorized to execute action review.'
    },
    {
      id: 'EDGE-01',
      title: 'Edge Case 1: Stale Indicator Dampening',
      category: 'Edge Case Resilience',
      description: 'Indicator inactive for >250 days with zero local telemetry.',
      payload: {
        indicator: '203.0.113.60',
        type: 'ipv4',
        confidence: 90,
        severity: 'high',
        last_seen: '2025-12-01 00:00:00'
      },
      endpoint: '/api/score',
      method: 'POST',
      validator: (res: any) =>
        res.threatlens?.breakdown?.staleness_penalty === -15 && res.threatlens?.score < 40,
      expected: 'Staleness Penalty (-15 pts) automatically applied; indicator suppressed.'
    },
    {
      id: 'EDGE-02',
      title: 'Edge Case 2: Shared CDN / Cloudflare Dampener',
      category: 'Edge Case Resilience',
      description: 'Known public multi-tenant CDN IP (104.16.124.96) reported in external feed.',
      payload: {
        indicator: '104.16.124.96',
        type: 'ipv4',
        confidence: 85,
        severity: 'high'
      },
      endpoint: '/api/score',
      method: 'POST',
      validator: (res: any) =>
        res.threatlens?.breakdown?.cdn_penalty === -25 && res.threatlens?.score < 50,
      expected: 'CDN Dampener (-25 pts) triggered to prevent blocking essential infrastructure.'
    }
  ];

  const runScenario = async (scenario: typeof scenarios[0]) => {
    setRunningTest(scenario.id);
    try {
      const res = await fetch(scenario.endpoint, {
        method: scenario.method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(scenario.payload)
      });
      const data = await res.json().catch(() => ({}));
      const passed = scenario.validator(data, res.status);

      setTestResults(prev => ({
        ...prev,
        [scenario.id]: {
          status: res.status,
          passed,
          data,
          timestamp: new Date().toLocaleTimeString()
        }
      }));
      onRefreshAll();
    } catch (err: any) {
      setTestResults(prev => ({
        ...prev,
        [scenario.id]: {
          status: 'ERROR',
          passed: false,
          error: err.message,
          timestamp: new Date().toLocaleTimeString()
        }
      }));
    } finally {
      setRunningTest(null);
    }
  };

  const runAllTests = async () => {
    for (const sc of scenarios) {
      await runScenario(sc);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Lock className="w-5 h-5 text-emerald-400" />
            <h2 className="text-lg font-bold text-slate-100">
              Security Attacks &amp; Edge Cases Test Suite
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Execute real adversarial test payloads against backend endpoints to verify score manipulation protection, RBAC boundaries, and edge resilience.
          </p>
        </div>

        <button
          onClick={runAllTests}
          className="inline-flex items-center space-x-2 px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold text-xs transition-colors shadow-md shadow-emerald-950"
        >
          <Play className="w-4 h-4" />
          <span>Execute Entire Test Suite</span>
        </button>
      </div>

      {/* Scenarios Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {scenarios.map(sc => {
          const res = testResults[sc.id];
          const isRunning = runningTest === sc.id;

          return (
            <div
              key={sc.id}
              className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between space-y-4"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-2">
                    <span className="font-mono text-xs font-bold text-emerald-400 px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800">
                      {sc.id}
                    </span>
                    <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                      {sc.category}
                    </span>
                  </div>

                  {res && (
                    <span
                      className={`inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-bold ${
                        res.passed
                          ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                          : 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                      }`}
                    >
                      {res.passed ? (
                        <CheckCircle2 className="w-3 h-3" />
                      ) : (
                        <XCircle className="w-3 h-3" />
                      )}
                      <span>{res.passed ? 'DEFENSE VERIFIED' : 'FAILED'}</span>
                    </span>
                  )}
                </div>

                <h3 className="text-sm font-bold text-slate-100">{sc.title}</h3>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">{sc.description}</p>

                <div className="mt-3 p-2.5 rounded-lg bg-slate-950 border border-slate-800/80 text-[11px] font-sans text-slate-300">
                  <strong className="text-slate-400">Expected:</strong> {sc.expected}
                </div>
              </div>

              {/* Action and Output */}
              <div className="space-y-2 pt-2 border-t border-slate-800">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-mono text-slate-500">
                    {sc.method} {sc.endpoint}
                  </span>
                  <button
                    disabled={isRunning}
                    onClick={() => runScenario(sc)}
                    className="inline-flex items-center space-x-1 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors"
                  >
                    <Play className="w-3 h-3 text-emerald-400" />
                    <span>{isRunning ? 'Executing...' : 'Run Attack / Test'}</span>
                  </button>
                </div>

                {res && (
                  <pre className="text-[10px] bg-slate-950 p-2.5 rounded border border-slate-800 text-emerald-400 font-mono overflow-x-auto max-h-32">
                    {JSON.stringify(res.data || res.error, null, 2)}
                  </pre>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
