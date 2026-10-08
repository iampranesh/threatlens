import React from 'react';
import { X, ShieldAlert, Zap, AlertTriangle, CheckCircle } from 'lucide-react';
import { Indicator, User } from '../server/types.ts';

interface ContainmentModalProps {
  indicator: Indicator;
  currentUser: User;
  onClose: () => void;
  onSuccess: () => void;
}

export const ContainmentModal: React.FC<ContainmentModalProps> = ({
  indicator,
  currentUser,
  onClose,
  onSuccess
}) => {
  const [actionType, setActionType] = React.useState<'BLOCK_FIREWALL' | 'ISOLATE_HOST' | 'SINKHOLE_DNS'>('BLOCK_FIREWALL');
  const [rationale, setRationale] = React.useState('');
  const [loading, setLoading] = React.useState(false);
  const [resultMsg, setResultMsg] = React.useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!rationale.trim()) {
      alert('A technical rationale is required before proposing high-impact containment.');
      return;
    }

    setLoading(true);
    try {
      const res = await fetch('/api/actions/propose', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          indicator: indicator.indicator,
          action_type: actionType,
          rationale
        })
      });
      const data = await res.json();
      if (!res.ok) {
        setResultMsg(`Error: ${data.error}`);
      } else {
        setResultMsg(data.message);
        setTimeout(() => {
          onSuccess();
          onClose();
        }, 1500);
      }
    } catch (err: any) {
      setResultMsg(`Failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-md p-6 space-y-4 shadow-2xl font-sans">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2">
            <Zap className="w-5 h-5 text-rose-500" />
            <h3 className="text-base font-bold text-slate-100">
              Propose Containment Action
            </h3>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-200">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-300 font-mono">
          Target: <strong className="text-slate-100">{indicator.indicator}</strong>
          <span className="block text-[11px] text-slate-400 font-sans mt-0.5">
            Score: {indicator.score} ({indicator.label})
          </span>
        </div>

        <div className="p-3 rounded-lg bg-amber-950/20 border border-amber-900/40 text-[11px] text-amber-300">
          <AlertTriangle className="w-3.5 h-3.5 inline mr-1 text-amber-400" />
          <strong>Human-in-the-Loop Policy:</strong> ThreatLens never executes automated blocking. This action will be queued for Reviewer or Admin approval before firewall dispatch.
        </div>

        {resultMsg && (
          <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-900/60 text-xs text-emerald-300">
            {resultMsg}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div>
            <label className="block text-slate-300 font-semibold mb-1">
              Containment Action Type
            </label>
            <select
              value={actionType}
              onChange={e => setActionType(e.target.value as any)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-rose-500"
            >
              <option value="BLOCK_FIREWALL">Border Firewall Ingress/Egress Drop</option>
              <option value="ISOLATE_HOST">EDR Host Isolation (VLAN Quarantine)</option>
              <option value="SINKHOLE_DNS">Internal DNS Sinkhole Blackhole</option>
            </select>
          </div>

          <div>
            <label className="block text-slate-300 font-semibold mb-1">
              SOC Investigation Rationale
            </label>
            <textarea
              rows={3}
              required
              placeholder="e.g. Active malicious telemetry confirmed on WEB-PROD-01 matching CVE-2024-3400..."
              value={rationale}
              onChange={e => setRationale(e.target.value)}
              className="w-full p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-rose-500"
            />
          </div>

          <div className="flex justify-end space-x-2 pt-2 border-t border-slate-800">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded-lg bg-slate-800 text-slate-300 hover:bg-slate-700"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="px-4 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-500 text-slate-950 font-bold"
            >
              {loading ? 'Submitting...' : 'Queue for Review'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
