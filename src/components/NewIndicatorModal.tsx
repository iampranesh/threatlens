import React from 'react';
import { X, Plus, ShieldCheck, AlertCircle } from 'lucide-react';
import { Indicator } from '../server/types.ts';

interface NewIndicatorModalProps {
  onClose: () => void;
  onIndicatorCreated: (ind: Indicator) => void;
}

export const NewIndicatorModal: React.FC<NewIndicatorModalProps> = ({
  onClose,
  onIndicatorCreated
}) => {
  const [indicator, setIndicator] = React.useState('');
  const [type, setType] = React.useState<'ipv4' | 'domain' | 'url' | 'sha256'>('ipv4');
  const [source, setSource] = React.useState('AlienVault-OTX-Syn');
  const [confidence, setConfidence] = React.useState(85);
  const [severity, setSeverity] = React.useState<'low' | 'medium' | 'high' | 'critical'>('high');
  const [cve, setCve] = React.useState('');
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!indicator.trim()) return;

    setLoading(true);
    setError(null);

    try {
      const res = await fetch('/api/indicators', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          indicator: indicator.trim(),
          type,
          source,
          confidence,
          severity,
          cve: cve.trim()
        })
      });

      const data = await res.json();
      if (!res.ok) {
        setError(data.reason || data.error || data.message || 'Failed to ingest indicator');
      } else {
        onIndicatorCreated(data.indicator);
        onClose();
      }
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm font-sans">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-lg p-6 space-y-4 shadow-2xl">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2">
            <Plus className="w-5 h-5 text-emerald-400" />
            <h3 className="text-base font-bold text-slate-100">
              Ingest &amp; Score Threat Indicator
            </h3>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-200">
            <X className="w-5 h-5" />
          </button>
        </div>

        <p className="text-xs text-slate-400">
          The server will independently validate the indicator, cross-reference organizational telemetry and inventory, and calculate an explainable local score.
        </p>

        {error && (
          <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-900/60 text-xs text-rose-300 flex items-center space-x-2">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4 text-xs">
          <div>
            <label className="block text-slate-300 font-semibold mb-1">
              Indicator Value
            </label>
            <input
              type="text"
              required
              placeholder="e.g. 198.51.100.99 or c2-beacon.attacker.org"
              value={indicator}
              onChange={e => setIndicator(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 font-mono focus:outline-none focus:border-emerald-500"
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-300 font-semibold mb-1">
                Indicator Type
              </label>
              <select
                value={type}
                onChange={e => setType(e.target.value as any)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-emerald-500"
              >
                <option value="ipv4">IPv4 Address</option>
                <option value="domain">Domain Name</option>
                <option value="url">URL</option>
                <option value="sha256">SHA256 Hash</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-300 font-semibold mb-1">
                Threat Feed Source
              </label>
              <select
                value={source}
                onChange={e => setSource(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-emerald-500"
              >
                <option value="AlienVault-OTX-Syn">AlienVault OTX (Syn)</option>
                <option value="AbuseIPDB-Syn">AbuseIPDB (Syn)</option>
                <option value="CrowdStrike-Falcon-Syn">CrowdStrike Falcon (Syn)</option>
                <option value="Mandiant-AdvThreat-Syn">Mandiant AdvThreat (Syn)</option>
                <option value="CISA-KnownExploited-Syn">CISA KEV (Syn)</option>
              </select>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-300 font-semibold mb-1">
                Feed Confidence ({confidence}%)
              </label>
              <input
                type="number"
                min="0"
                max="100"
                value={confidence}
                onChange={e => setConfidence(Number(e.target.value))}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 font-mono focus:outline-none focus:border-emerald-500"
              />
            </div>

            <div>
              <label className="block text-slate-300 font-semibold mb-1">
                Feed Severity
              </label>
              <select
                value={severity}
                onChange={e => setSeverity(e.target.value as any)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 focus:outline-none focus:border-emerald-500"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-slate-300 font-semibold mb-1">
              Associated CVE (Optional)
            </label>
            <input
              type="text"
              placeholder="e.g. CVE-2024-3400 or CVE-2021-41773"
              value={cve}
              onChange={e => setCve(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 font-mono focus:outline-none focus:border-emerald-500"
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
              className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold"
            >
              {loading ? 'Evaluating...' : 'Ingest & Evaluate'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
