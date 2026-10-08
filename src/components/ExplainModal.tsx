import React from 'react';
import {
  X,
  ShieldAlert,
  ShieldCheck,
  CheckCircle,
  AlertTriangle,
  Server,
  Activity,
  History,
  FileCode,
  Zap,
  Lock,
  ExternalLink
} from 'lucide-react';
import { Indicator, Asset, TrafficObservation, HistoricalIncident } from '../server/types.ts';

interface ExplainModalProps {
  indicator: Indicator;
  onClose: () => void;
  onProposeAction: (ind: Indicator) => void;
}

export const ExplainModal: React.FC<ExplainModalProps> = ({
  indicator,
  onClose,
  onProposeAction
}) => {
  const [evidenceData, setEvidenceData] = React.useState<any>(null);
  const [loading, setLoading] = React.useState(true);

  React.useEffect(() => {
    fetch(`/api/evidence/${indicator.indicator_id}`)
      .then(res => res.json())
      .then(data => {
        setEvidenceData(data);
        setLoading(false);
      })
      .catch(err => {
        console.error('Failed to load evidence details:', err);
        setLoading(false);
      });
  }, [indicator]);

  const breakdown = indicator.breakdown || evidenceData?.factor_breakdown || {};
  const evidenceList = indicator.evidence || evidenceData?.evidence_chain || [];

  const getScoreColor = (score?: number) => {
    if (!score) return 'text-slate-400';
    if (score >= 80) return 'text-rose-400';
    if (score >= 60) return 'text-amber-400';
    if (score >= 40) return 'text-yellow-400';
    if (score >= 20) return 'text-blue-400';
    return 'text-slate-400';
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm overflow-y-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-4xl max-h-[90vh] overflow-y-auto shadow-2xl">
        {/* Modal Header */}
        <div className="p-6 border-b border-slate-800 flex items-start justify-between sticky top-0 bg-slate-900 z-10">
          <div>
            <div className="flex items-center space-x-3">
              <h2 className="text-xl font-bold font-mono text-slate-100">{indicator.indicator}</h2>
              <span
                className={`px-2.5 py-0.5 rounded text-xs font-bold ${
                  indicator.label === 'CRITICAL'
                    ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                    : indicator.label === 'HIGH'
                    ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                    : indicator.label === 'MEDIUM'
                    ? 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30'
                    : 'bg-slate-800 text-slate-400 border border-slate-700'
                }`}
              >
                {indicator.label}
              </span>
              <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-400 font-sans uppercase">
                {indicator.type}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-1 font-sans">
              Ingested via <span className="text-slate-300 font-medium">{indicator.source}</span> (Feed Confidence: {indicator.confidence}%)
            </p>
          </div>

          <div className="flex items-center space-x-3">
            <button
              onClick={() => onProposeAction(indicator)}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-slate-950 font-bold text-xs transition-colors shadow-md shadow-rose-950"
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Containment Action</span>
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6">
          {/* Score & Executive Explanation Box */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 p-5 rounded-xl bg-slate-950/80 border border-slate-800">
            {/* Score Metric */}
            <div className="flex flex-col justify-center items-center p-4 bg-slate-900 rounded-lg border border-slate-800 text-center">
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                ThreatLens Score
              </span>
              <div className={`text-4xl font-extrabold tracking-tight mt-1 font-mono ${getScoreColor(indicator.score)}`}>
                {indicator.score}
              </div>
              <span className="text-[10px] text-slate-500 mt-1 font-mono">Range 0–100</span>
            </div>

            {/* Explanation Statement */}
            <div className="md:col-span-3 flex flex-col justify-center space-y-2">
              <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center space-x-1">
                <ShieldCheck className="w-4 h-4" />
                <span>Explainability Verdict</span>
              </span>
              <p className="text-sm text-slate-200 leading-relaxed font-sans">
                {indicator.explanation || 'Analyzed against internal software inventory and network telemetry.'}
              </p>
              <div className="flex items-center space-x-4 text-xs text-slate-400 pt-1 font-mono">
                <span>Baseline Feed Score: <strong className="text-slate-300">{indicator.baseline_score ?? 60}</strong></span>
                <span>•</span>
                <span>Affected Asset: <strong className="text-sky-400">{indicator.matched_asset || 'NONE'}</strong></span>
              </div>
            </div>
          </div>

          {/* Evidence Chain Checklist */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
              <CheckCircle className="w-4 h-4 text-emerald-400" />
              <span>Corroborated Evidence Chain</span>
            </h3>

            {evidenceList.length === 0 ? (
              <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 text-xs text-slate-400">
                <AlertTriangle className="w-4 h-4 text-yellow-400 inline mr-2" />
                <strong>INSUFFICIENT LOCAL EVIDENCE:</strong> No matching internal network connections, vulnerable software installations, or past incidents detected. Indicator suppressed from primary alert queue.
              </div>
            ) : (
              <div className="grid grid-cols-1 gap-2">
                {evidenceList.map((item: string, idx: number) => {
                  const isPenalty = item.includes('Penalty') || item.includes('dampener');
                  return (
                    <div
                      key={idx}
                      className={`flex items-start space-x-3 p-3 rounded-lg border text-xs font-sans ${
                        isPenalty
                          ? 'bg-amber-950/20 border-amber-900/40 text-amber-200/90'
                          : 'bg-emerald-950/20 border-emerald-900/40 text-emerald-200/90'
                      }`}
                    >
                      <span className="font-bold text-sm leading-none mt-0.5">
                        {isPenalty ? '⚠' : '✓'}
                      </span>
                      <span>{item}</span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Factor Breakdown (Waterfall Breakdown) */}
          <div className="space-y-3">
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center space-x-2">
              <Activity className="w-4 h-4 text-sky-400" />
              <span>Factor Contribution Breakdown</span>
            </h3>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono text-xs">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-sans block">Observed Traffic</span>
                <span className="text-base font-bold text-sky-400">+{breakdown.traffic ?? 0}</span>
                <span className="text-[10px] text-slate-500 font-sans block">Max: 30 pts</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-sans block">Historical Incident</span>
                <span className="text-base font-bold text-purple-400">+{breakdown.incident ?? 0}</span>
                <span className="text-[10px] text-slate-500 font-sans block">Max: 25 pts</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-sans block">Software / CVE Match</span>
                <span className="text-base font-bold text-indigo-400">+{breakdown.software_cve ?? 0}</span>
                <span className="text-[10px] text-slate-500 font-sans block">Max: 20 pts</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-sans block">Perimeter Exposure</span>
                <span className="text-base font-bold text-emerald-400">+{breakdown.exposure ?? 0}</span>
                <span className="text-[10px] text-slate-500 font-sans block">Max: 15 pts</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-sans block">Asset Criticality</span>
                <span className="text-base font-bold text-slate-300">+{breakdown.asset_criticality ?? 0}</span>
                <span className="text-[10px] text-slate-500 font-sans block">Max: 10 pts</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-sans block">Feed Reputation</span>
                <span className="text-base font-bold text-slate-300">+{breakdown.feed_reputation ?? 0}</span>
                <span className="text-[10px] text-slate-500 font-sans block">Max: 10 pts</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-sans block">Temporal Recency</span>
                <span className="text-base font-bold text-slate-300">+{breakdown.recency ?? 0}</span>
                <span className="text-[10px] text-slate-500 font-sans block">Max: 10 pts</span>
              </div>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
                <span className="text-[10px] text-slate-400 font-sans block">Dampening Penalties</span>
                <span className="text-base font-bold text-rose-400">
                  {(breakdown.staleness_penalty || 0) +
                    (breakdown.weak_evidence_penalty || 0) +
                    (breakdown.cdn_penalty || 0)}
                </span>
                <span className="text-[10px] text-slate-500 font-sans block">Stale / CDN / Weak</span>
              </div>
            </div>
          </div>

          {/* Deep Context Tabs (Telemetry logs & Asset info) */}
          {evidenceData && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Asset Card */}
              {evidenceData.associated_asset && (
                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
                  <div className="flex items-center space-x-2 text-xs font-bold text-sky-400 uppercase tracking-wider">
                    <Server className="w-4 h-4" />
                    <span>Targeted Organizational Asset</span>
                  </div>
                  <div className="text-sm font-bold text-slate-100">
                    {evidenceData.associated_asset.asset_id} — {evidenceData.associated_asset.hostname}
                  </div>
                  <div className="text-xs text-slate-400 space-y-1">
                    <div><strong>Application:</strong> {evidenceData.associated_asset.application} v{evidenceData.associated_asset.version}</div>
                    <div><strong>OS:</strong> {evidenceData.associated_asset.operating_system}</div>
                    <div><strong>Internet Exposed:</strong> {evidenceData.associated_asset.internet_exposed ? 'YES' : 'NO'}</div>
                    <div><strong>Criticality:</strong> <span className="uppercase text-amber-400 font-semibold">{evidenceData.associated_asset.criticality}</span></div>
                  </div>
                </div>
              )}

              {/* Incidents Card */}
              {evidenceData.historical_incidents && evidenceData.historical_incidents.length > 0 && (
                <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-2">
                  <div className="flex items-center space-x-2 text-xs font-bold text-purple-400 uppercase tracking-wider">
                    <History className="w-4 h-4" />
                    <span>Correlated Incident Records</span>
                  </div>
                  {evidenceData.historical_incidents.map((inc: any) => (
                    <div key={inc.incident_id} className="text-xs text-slate-300 border-b border-slate-800/80 pb-2 last:border-none">
                      <div className="font-bold text-slate-200">{inc.incident_id}: {inc.incident_type}</div>
                      <div className="text-slate-400 text-[11px]">{inc.date} • Impact: {inc.business_impact}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Network Telemetry Log Sample */}
          {evidenceData?.telemetry_logs && evidenceData.telemetry_logs.length > 0 && (
            <div className="space-y-2">
              <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                Raw Network Telemetry Session Samples ({evidenceData.telemetry_logs.length} Total Logs)
              </h4>
              <div className="overflow-x-auto max-h-48 border border-slate-800 rounded-lg">
                <table className="w-full text-left text-[11px] font-mono text-slate-300">
                  <thead className="bg-slate-950 text-slate-400 uppercase text-[10px]">
                    <tr>
                      <th className="p-2">Timestamp</th>
                      <th className="p-2">Source IP</th>
                      <th className="p-2">Destination IP</th>
                      <th className="p-2">Port/Proto</th>
                      <th className="p-2">Action</th>
                      <th className="p-2">Bytes</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {evidenceData.telemetry_logs.slice(0, 5).map((log: any) => (
                      <tr key={log.traffic_id} className="hover:bg-slate-850">
                        <td className="p-2 text-slate-400">{log.timestamp}</td>
                        <td className="p-2 text-slate-200">{log.source_ip}</td>
                        <td className="p-2 text-slate-200">{log.destination_ip}</td>
                        <td className="p-2">{log.port} / {log.protocol}</td>
                        <td className="p-2">
                          <span className={`px-1.5 py-0.2 rounded font-semibold ${log.action === 'allowed' ? 'text-rose-400 bg-rose-950/40' : 'text-slate-400 bg-slate-800'}`}>
                            {log.action}
                          </span>
                        </td>
                        <td className="p-2 text-slate-400">{log.bytes} B</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
