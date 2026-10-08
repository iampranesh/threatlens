import React from 'react';
import {
  Sliders,
  History,
  RotateCcw,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Lock,
  PlusCircle,
  FileCheck
} from 'lucide-react';
import { ScoringConfig, User } from '../server/types.ts';

interface GovernanceViewProps {
  currentUser: User;
  onRefreshData: () => void;
}

export const GovernanceView: React.FC<GovernanceViewProps> = ({
  currentUser,
  onRefreshData
}) => {
  const [configData, setConfigData] = React.useState<{
    active_config?: ScoringConfig;
    history?: ScoringConfig[];
  }>({});
  const [loading, setLoading] = React.useState(true);
  const [proposeModal, setProposeModal] = React.useState(false);
  const [statusMessage, setStatusMessage] = React.useState<string | null>(null);

  // Form states
  const [trafficWeight, setTrafficWeight] = React.useState(30);
  const [incidentWeight, setIncidentWeight] = React.useState(25);
  const [cveWeight, setCveWeight] = React.useState(20);
  const [reason, setReason] = React.useState('');

  const fetchConfig = () => {
    fetch('/api/config')
      .then(res => res.json())
      .then(data => {
        setConfigData(data);
        if (data.active_config) {
          setTrafficWeight(data.active_config.traffic_weight);
          setIncidentWeight(data.active_config.incident_weight);
          setCveWeight(data.active_config.cve_weight);
        }
        setLoading(false);
      });
  };

  React.useEffect(() => {
    fetchConfig();
  }, []);

  const handlePropose = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!reason.trim()) {
      alert('A valid rationale is required for proposing a configuration change.');
      return;
    }

    try {
      const res = await fetch('/api/config/change', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          traffic_weight: trafficWeight,
          incident_weight: incidentWeight,
          cve_weight: cveWeight,
          reason
        })
      });
      const data = await res.json();
      if (!res.ok) {
        setStatusMessage(`Error: ${data.message || data.error}`);
      } else {
        setStatusMessage(data.message);
        setProposeModal(false);
        setReason('');
        fetchConfig();
        onRefreshData();
      }
    } catch (err: any) {
      setStatusMessage(`Failed: ${err.message}`);
    }
  };

  const handleReview = async (version: number, decision: 'APPROVE' | 'REJECT') => {
    try {
      const res = await fetch('/api/config/review', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          version,
          decision,
          notes: `${decision} by ${currentUser.name} (${currentUser.role})`
        })
      });
      const data = await res.json();
      if (!res.ok) {
        setStatusMessage(`Error: ${data.message || data.error}`);
      } else {
        setStatusMessage(data.message);
        fetchConfig();
        onRefreshData();
      }
    } catch (err: any) {
      setStatusMessage(`Failed: ${err.message}`);
    }
  };

  const handleRollback = async (targetVersion: number) => {
    if (!confirm(`Are you sure you want to rollback active scoring to Version ${targetVersion}?`)) {
      return;
    }

    try {
      const res = await fetch('/api/config/rollback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetVersion,
          reason: `Rollback triggered by ${currentUser.name} (${currentUser.role})`
        })
      });
      const data = await res.json();
      if (!res.ok) {
        setStatusMessage(`Error: ${data.message || data.error}`);
      } else {
        setStatusMessage(data.message);
        fetchConfig();
        onRefreshData();
      }
    } catch (err: any) {
      setStatusMessage(`Failed: ${err.message}`);
    }
  };

  const active = configData.active_config;
  const history = configData.history || [];
  const pending = history.filter(c => c.status === 'PENDING_REVIEW');

  const isAdmin = currentUser.role === 'ADMIN';
  const isReviewerOrAdmin = currentUser.role === 'REVIEWER' || currentUser.role === 'ADMIN';

  return (
    <div className="space-y-6">
      {/* Status Alert Banner */}
      {statusMessage && (
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-700 flex items-center justify-between text-xs text-slate-200">
          <div className="flex items-center space-x-2">
            <CheckCircle className="w-4 h-4 text-emerald-400" />
            <span>{statusMessage}</span>
          </div>
          <button
            onClick={() => setStatusMessage(null)}
            className="text-slate-400 hover:text-slate-200"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Header and Actions */}
      <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Sliders className="w-5 h-5 text-emerald-400" />
            <h2 className="text-lg font-bold text-slate-100">
              Scoring Governance &amp; Versioned Rollback
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Transparent algorithmic parameters. All modifications require formal proposal, Reviewer or Admin review, and support 1-click rollback.
          </p>
        </div>

        <button
          onClick={() => {
            if (!isAdmin) {
              setStatusMessage('Access Denied: Only ADMIN can propose configuration changes.');
              return;
            }
            setProposeModal(true);
          }}
          className={`inline-flex items-center space-x-2 px-3.5 py-2 rounded-lg text-xs font-semibold transition-colors shadow-sm ${
            isAdmin
              ? 'bg-purple-600 hover:bg-purple-500 text-slate-950'
              : 'bg-slate-800 text-slate-500 cursor-not-allowed border border-slate-700'
          }`}
        >
          <PlusCircle className="w-4 h-4" />
          <span>Propose Config Change {isAdmin ? '' : '(Admin Only)'}</span>
        </button>
      </div>

      {/* Active Configuration Card */}
      {active && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <span className="px-2.5 py-0.5 rounded text-xs font-bold bg-emerald-500/15 text-emerald-400 border border-emerald-500/30">
                ACTIVE VERSION {active.version}
              </span>
              <span className="text-xs text-slate-400 font-sans">
                Activated by {active.created_by}
              </span>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              {active.created_at}
            </span>
          </div>

          <p className="text-xs text-slate-300 italic font-sans bg-slate-950 p-3 rounded-lg border border-slate-800/80">
            "{active.review_reason || 'Certified active production configuration.'}"
          </p>

          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3 text-xs font-mono">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-400 block font-sans">Traffic Telemetry</span>
              <span className="text-lg font-bold text-sky-400">{active.traffic_weight} pts</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-400 block font-sans">Incident History</span>
              <span className="text-lg font-bold text-purple-400">{active.incident_weight} pts</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-400 block font-sans">Software / CVE</span>
              <span className="text-lg font-bold text-indigo-400">{active.cve_weight} pts</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-400 block font-sans">Perimeter Exposure</span>
              <span className="text-lg font-bold text-emerald-400">{active.exposure_weight} pts</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-400 block font-sans">Feed Reputation</span>
              <span className="text-lg font-bold text-slate-300">{active.feed_weight} pts</span>
            </div>
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-400 block font-sans">Weak Evidence Penalty</span>
              <span className="text-lg font-bold text-rose-400">-{active.weak_evidence_penalty} pts</span>
            </div>
          </div>
        </div>
      )}

      {/* Pending Proposals Queue */}
      {pending.length > 0 && (
        <div className="bg-slate-900 border border-amber-900/40 rounded-xl p-5 space-y-4">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-4 h-4 text-amber-400" />
            <h3 className="text-sm font-bold text-amber-300 uppercase tracking-wider">
              Pending Configuration Proposals Awaiting Review ({pending.length})
            </h3>
          </div>

          <div className="space-y-3">
            {pending.map(prop => (
              <div key={prop.version} className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <div className="flex items-center space-x-2">
                    <span className="font-bold text-slate-100 font-mono text-sm">Version {prop.version} Proposal</span>
                    <span className="text-xs text-slate-400 font-sans">by {prop.created_by}</span>
                  </div>
                  <p className="text-xs text-slate-300 mt-1 font-sans">
                    <strong>Rationale:</strong> {prop.review_reason}
                  </p>
                  <div className="flex items-center space-x-4 text-xs font-mono text-slate-400 mt-2">
                    <span>Traffic: {prop.traffic_weight} pts</span>
                    <span>•</span>
                    <span>Incidents: {prop.incident_weight} pts</span>
                    <span>•</span>
                    <span>CVE: {prop.cve_weight} pts</span>
                  </div>
                </div>

                <div className="flex items-center space-x-2">
                  <button
                    disabled={!isReviewerOrAdmin}
                    onClick={() => handleReview(prop.version, 'APPROVE')}
                    className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-colors ${
                      isReviewerOrAdmin
                        ? 'bg-emerald-600 hover:bg-emerald-500 text-slate-950'
                        : 'bg-slate-800 text-slate-600 cursor-not-allowed'
                    }`}
                  >
                    Approve &amp; Activate {isReviewerOrAdmin ? '' : '(Reviewer Only)'}
                  </button>
                  <button
                    disabled={!isReviewerOrAdmin}
                    onClick={() => handleReview(prop.version, 'REJECT')}
                    className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-colors ${
                      isReviewerOrAdmin
                        ? 'bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-800'
                        : 'bg-slate-800 text-slate-600 cursor-not-allowed'
                    }`}
                  >
                    Reject
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Version History & Rollback Timeline */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-200 flex items-center space-x-2">
              <History className="w-4 h-4 text-sky-400" />
              <span>Configuration Version History &amp; Instant Rollback</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Rollback restores scoring weights, recalculates all indicators, and logs an immutable audit event.
            </p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/70 text-slate-400 uppercase font-semibold text-[11px]">
                <th className="py-3 px-4">Version</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Weights Summary</th>
                <th className="py-3 px-4">Change Rationale</th>
                <th className="py-3 px-4">Author</th>
                <th className="py-3 px-4 text-right">Rollback Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-sans text-slate-300">
              {history.map(item => (
                <tr key={item.version} className="hover:bg-slate-800/30">
                  <td className="py-3 px-4 font-mono font-bold text-slate-100">
                    v{item.version}
                  </td>
                  <td className="py-3 px-4 font-mono">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        item.status === 'ACTIVE'
                          ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                          : item.status === 'PENDING_REVIEW'
                          ? 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      {item.status}
                    </span>
                  </td>
                  <td className="py-3 px-4 font-mono text-[11px] text-slate-400">
                    Trf: {item.traffic_weight} | Inc: {item.incident_weight} | CVE: {item.cve_weight}
                  </td>
                  <td className="py-3 px-4 text-slate-300 max-w-xs truncate">
                    {item.review_reason}
                  </td>
                  <td className="py-3 px-4 text-slate-400">
                    {item.created_by}
                  </td>
                  <td className="py-3 px-4 text-right">
                    {item.status !== 'ACTIVE' && item.status !== 'PENDING_REVIEW' && (
                      <button
                        disabled={!isAdmin}
                        onClick={() => handleRollback(item.version)}
                        className={`inline-flex items-center space-x-1 px-2.5 py-1 rounded text-xs font-semibold transition-colors ${
                          isAdmin
                            ? 'bg-sky-950 hover:bg-sky-900 text-sky-400 border border-sky-800'
                            : 'bg-slate-800 text-slate-600 cursor-not-allowed'
                        }`}
                      >
                        <RotateCcw className="w-3 h-3" />
                        <span>Rollback {isAdmin ? '' : '(Admin)'}</span>
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Propose Change Modal */}
      {proposeModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-lg p-6 space-y-4 shadow-2xl">
            <h3 className="text-base font-bold text-slate-100">
              Propose Scoring Configuration Change
            </h3>
            <p className="text-xs text-slate-400">
              Proposed changes are staged for independent Reviewer sign-off before becoming active.
            </p>

            <form onSubmit={handlePropose} className="space-y-4 text-xs font-sans">
              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Traffic Telemetry Weight ({trafficWeight} pts)
                </label>
                <input
                  type="range"
                  min="10"
                  max="50"
                  value={trafficWeight}
                  onChange={e => setTrafficWeight(Number(e.target.value))}
                  className="w-full"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Historical Incident Weight ({incidentWeight} pts)
                </label>
                <input
                  type="range"
                  min="10"
                  max="40"
                  value={incidentWeight}
                  onChange={e => setIncidentWeight(Number(e.target.value))}
                  className="w-full"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Software / CVE Match Weight ({cveWeight} pts)
                </label>
                <input
                  type="range"
                  min="10"
                  max="40"
                  value={cveWeight}
                  onChange={e => setCveWeight(Number(e.target.value))}
                  className="w-full"
                />
              </div>

              <div>
                <label className="block text-slate-300 font-semibold mb-1">
                  Mandatory Change Rationale
                </label>
                <textarea
                  rows={3}
                  required
                  placeholder="e.g. Telemetry correlation backtesting indicated higher predictive power..."
                  value={reason}
                  onChange={e => setReason(e.target.value)}
                  className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-purple-500"
                />
              </div>

              <div className="flex justify-end space-x-2 pt-2">
                <button
                  type="button"
                  onClick={() => setProposeModal(false)}
                  className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-slate-950 font-bold"
                >
                  Submit Proposal
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
