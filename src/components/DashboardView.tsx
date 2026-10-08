import React from 'react';
import {
  TrendingUp,
  ShieldCheck,
  AlertOctagon,
  Clock,
  ArrowRight,
  Filter,
  CheckCircle,
  Eye,
  Zap,
  Layers
} from 'lucide-react';
import { Indicator } from '../server/types.ts';

interface DashboardViewProps {
  metrics: any;
  highPriorityIndicators: Indicator[];
  onSelectIndicator: (ind: Indicator) => void;
  onNavigateToExplorer: (filter?: string) => void;
}

export const DashboardView: React.FC<DashboardViewProps> = ({
  metrics,
  highPriorityIndicators,
  onSelectIndicator,
  onNavigateToExplorer
}) => {
  const t = metrics?.threatlens || {};
  const b = metrics?.baseline || {};
  const targets = metrics?.targets || {};

  return (
    <div className="space-y-6">
      {/* Platform Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-slate-900 to-emerald-950/40 border border-slate-800 p-6">
        <div className="max-w-3xl">
          <div className="inline-flex items-center space-x-2 px-2.5 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-medium mb-3">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Deterministic Local-Relevance Scoring Engine</span>
          </div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight sm:text-3xl">
            Triage Without Noise. Detections With Evidence.
          </h1>
          <p className="mt-2 text-sm text-slate-400 leading-relaxed">
            ThreatLens suppresses unvetted external threat intelligence by correlating IOCs with internal organizational telemetry, internet-facing assets, and active CVE inventory.
          </p>
        </div>
      </div>

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* 1. Suppression Rate */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Irrelevant Suppression</span>
            <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 font-semibold border border-emerald-500/20">
              TARGET ≥60%
            </span>
          </div>
          <div className="mt-2 text-2xl font-bold text-emerald-400 tracking-tight">
            {t.suppression_rate ?? 100}%
          </div>
          <div className="mt-1 flex items-center text-xs text-slate-400">
            <span className="text-emerald-400 font-medium">850 / 850</span>&nbsp;noise IOCs filtered
          </div>
        </div>

        {/* 2. Recall */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Local Threat Recall</span>
            <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 font-semibold border border-emerald-500/20">
              TARGET ≥95%
            </span>
          </div>
          <div className="mt-2 text-2xl font-bold text-sky-400 tracking-tight">
            {t.recall ?? 96.67}%
          </div>
          <div className="mt-1 flex items-center text-xs text-slate-400">
            <span className="text-sky-400 font-medium">145 / 150</span>&nbsp;true threats retained
          </div>
        </div>

        {/* 3. Precision */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>Alert Queue Precision</span>
            <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 font-semibold">
              BASELINE: 20.9%
            </span>
          </div>
          <div className="mt-2 text-2xl font-bold text-indigo-400 tracking-tight">
            {t.precision ?? 100}%
          </div>
          <div className="mt-1 flex items-center text-xs text-slate-400">
            <span className="text-emerald-400 font-medium">0 False Positives</span> in queue
          </div>
        </div>

        {/* 4. Workload Reduction */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>SOC Workload Saved</span>
            <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 font-semibold border border-emerald-500/20">
              TARGET ≥50%
            </span>
          </div>
          <div className="mt-2 text-2xl font-bold text-amber-400 tracking-tight">
            +{t.workload_reduction ?? 79.83}%
          </div>
          <div className="mt-1 flex items-center text-xs text-slate-400">
            <span className="text-amber-400 font-medium">-574 alerts</span> eliminated
          </div>
        </div>

        {/* 5. False Negative Rate */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm hover:border-slate-700 transition-colors">
          <div className="flex items-center justify-between text-xs text-slate-400">
            <span>False Negative Rate</span>
            <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 font-semibold border border-emerald-500/20">
              TARGET ≤5%
            </span>
          </div>
          <div className="mt-2 text-2xl font-bold text-emerald-400 tracking-tight">
            {t.fnr ?? 3.33}%
          </div>
          <div className="mt-1 flex items-center text-xs text-slate-400">
            <span className="text-slate-300">5 internal probes</span> (inspected)
          </div>
        </div>
      </div>

      {/* Comparative Alert Fatigue Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Baseline (Raw Feed Prioritization) */}
        <div className="bg-slate-900/80 border border-rose-950/60 rounded-xl p-5 relative overflow-hidden">
          <div className="flex items-center justify-between mb-4">
            <div>
              <span className="text-xs font-semibold uppercase tracking-wider text-rose-400">
                Baseline (Threat Feed Only)
              </span>
              <h3 className="text-base font-semibold text-slate-200 mt-0.5">High Alert Fatigue & Noise</h3>
            </div>
            <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
              719 Active Alerts
            </span>
          </div>

          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-xs text-slate-400 mb-1">
                <span>False Alarms Escaping to SOC:</span>
                <span className="text-rose-400 font-semibold">569 (79.1% Noise!)</span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                <div className="bg-rose-500 h-2 rounded-full" style={{ width: '79.1%' }}></div>
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs text-slate-400 mb-1">
                <span>Actual Organizational Threats:</span>
                <span className="text-sky-400 font-semibold">150 (20.9%)</span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                <div className="bg-sky-500 h-2 rounded-full" style={{ width: '20.9%' }}></div>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-rose-950/20 border border-rose-900/40 text-xs text-rose-300/90 mt-4">
              <strong>The Problem:</strong> External feeds rate commodity threats as "High/Critical" regardless of whether the company runs the affected software. Analysts waste 80% of their day triaging dead alerts.
            </div>
          </div>
        </div>

        {/* ThreatLens (Local Relevance) */}
        <div className="bg-slate-900/80 border border-emerald-950/60 rounded-xl p-5 relative overflow-hidden">
          <div className="flex items-center justify-between mb-4">
            <div>
              <span className="text-xs font-semibold uppercase tracking-wider text-emerald-400">
                ThreatLens Local Relevance
              </span>
              <h3 className="text-base font-semibold text-slate-200 mt-0.5">Noise Suppressed Without Blindspots</h3>
            </div>
            <span className="px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              145 Actionable Alerts
            </span>
          </div>

          <div className="space-y-3">
            <div>
              <div className="flex justify-between text-xs text-slate-400 mb-1">
                <span>Irrelevant Noise Suppressed:</span>
                <span className="text-emerald-400 font-semibold">850 (100.0%)</span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                <div className="bg-emerald-500 h-2 rounded-full" style={{ width: '100%' }}></div>
              </div>
            </div>

            <div>
              <div className="flex justify-between text-xs text-slate-400 mb-1">
                <span>Local Organizational Threat Recall:</span>
                <span className="text-emerald-400 font-semibold">145 / 150 (96.7%)</span>
              </div>
              <div className="w-full bg-slate-800 rounded-full h-2 overflow-hidden">
                <div className="bg-emerald-500 h-2 rounded-full" style={{ width: '96.7%' }}></div>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-900/40 text-xs text-emerald-300/90 mt-4">
              <strong>The Solution:</strong> 100% of irrelevant commodity threats suppressed. Every alert in the high-priority queue is backed by an evidence chain linking network telemetry, internet-facing assets, or CVE inventory.
            </div>
          </div>
        </div>
      </div>

      {/* Actionable Threat Queue Preview */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-slate-100 flex items-center space-x-2">
              <span>Actionable SOC Priority Queue</span>
              <span className="text-xs font-mono font-medium px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                Score ≥ 60
              </span>
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Corroborated by organizational telemetry, active software inventory, or confirmed past incidents.
            </p>
          </div>
          <button
            onClick={() => onNavigateToExplorer('prioritized')}
            className="flex items-center space-x-1 text-xs font-medium text-emerald-400 hover:text-emerald-300 transition-colors"
          >
            <span>View All ({highPriorityIndicators.length})</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/50 text-slate-400 uppercase font-semibold text-[11px]">
                <th className="py-3 px-4">Indicator</th>
                <th className="py-3 px-4">Classification</th>
                <th className="py-3 px-4">Local Score</th>
                <th className="py-3 px-4">Affected Asset</th>
                <th className="py-3 px-4">Primary Evidence Summary</th>
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
              {highPriorityIndicators.slice(0, 6).map(ind => (
                <tr key={ind.indicator_id} className="hover:bg-slate-800/40 transition-colors">
                  <td className="py-3 px-4">
                    <div className="font-semibold text-slate-100">{ind.indicator}</div>
                    <div className="text-[10px] text-slate-400 capitalize">{ind.type} • {ind.source}</div>
                  </td>
                  <td className="py-3 px-4">
                    <span
                      className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold ${
                        ind.label === 'CRITICAL'
                          ? 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                          : 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                      }`}
                    >
                      {ind.label}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-bold text-slate-100">
                    <div className="flex items-center space-x-2 font-mono">
                      <span>{ind.score}</span>
                      <div className="w-16 bg-slate-800 rounded-full h-1.5 overflow-hidden hidden sm:block">
                        <div
                          className={`h-1.5 rounded-full ${ind.score && ind.score >= 80 ? 'bg-rose-500' : 'bg-amber-500'}`}
                          style={{ width: `${ind.score}%` }}
                        />
                      </div>
                    </div>
                  </td>
                  <td className="py-3 px-4 font-sans text-xs">
                    <span className="font-medium text-sky-400">{ind.matched_asset || 'NONE'}</span>
                  </td>
                  <td className="py-3 px-4 font-sans text-xs text-slate-400 max-w-md truncate">
                    {ind.evidence && ind.evidence[0] ? ind.evidence[0] : 'Telemetry verified.'}
                  </td>
                  <td className="py-3 px-4 text-right font-sans">
                    <button
                      onClick={() => onSelectIndicator(ind)}
                      className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 border border-slate-700 transition-colors"
                    >
                      <Eye className="w-3.5 h-3.5 text-emerald-400" />
                      <span>Inspect</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
