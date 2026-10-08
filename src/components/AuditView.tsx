import React from 'react';
import {
  FileText,
  Search,
  Filter,
  CheckCircle,
  XCircle,
  AlertTriangle,
  RotateCcw,
  Eye,
  Lock
} from 'lucide-react';
import { AuditEvent } from '../server/types.ts';

export const AuditView: React.FC = () => {
  const [events, setEvents] = React.useState<AuditEvent[]>([]);
  const [search, setSearch] = React.useState('');
  const [roleFilter, setRoleFilter] = React.useState('ALL');
  const [resultFilter, setResultFilter] = React.useState('ALL');
  const [selectedEvent, setSelectedEvent] = React.useState<AuditEvent | null>(null);
  const [loading, setLoading] = React.useState(true);

  const fetchAudit = () => {
    fetch('/api/audit')
      .then(res => res.json())
      .then(data => {
        setEvents(data.events || []);
        setLoading(false);
      });
  };

  React.useEffect(() => {
    fetchAudit();
  }, []);

  const filtered = React.useMemo(() => {
    return events.filter(e => {
      if (search.trim()) {
        const q = search.toLowerCase();
        const match =
          e.user.toLowerCase().includes(q) ||
          e.action.toLowerCase().includes(q) ||
          e.resource.toLowerCase().includes(q) ||
          (e.reason && e.reason.toLowerCase().includes(q)) ||
          e.request_id.toLowerCase().includes(q);
        if (!match) return false;
      }
      if (roleFilter !== 'ALL' && e.role !== roleFilter) return false;
      if (resultFilter !== 'ALL' && e.result !== resultFilter) return false;
      return true;
    });
  }, [events, search, roleFilter, resultFilter]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="bg-slate-900 border border-slate-800 p-5 rounded-xl flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <FileText className="w-5 h-5 text-emerald-400" />
            <h2 className="text-lg font-bold text-slate-100">
              SOC Tamper-Evident Audit Trail
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Immutable log of all user actions, scoring computations, policy reviews, rollbacks, and authorization boundaries.
          </p>
        </div>

        <button
          onClick={fetchAudit}
          className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-300 border border-slate-700 transition-colors"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Refresh Events</span>
        </button>
      </div>

      {/* Filter Bar */}
      <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl flex flex-col sm:flex-row gap-3">
        <div className="flex-1 relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search by User, Action, Resource, or Request ID..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
          />
        </div>

        <select
          value={roleFilter}
          onChange={e => setRoleFilter(e.target.value)}
          className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
        >
          <option value="ALL">All Roles</option>
          <option value="ANALYST">Analyst</option>
          <option value="REVIEWER">Reviewer</option>
          <option value="ADMIN">Admin</option>
        </select>

        <select
          value={resultFilter}
          onChange={e => setResultFilter(e.target.value)}
          className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
        >
          <option value="ALL">All Results</option>
          <option value="SUCCESS">Success Only</option>
          <option value="DENIED">Denied / Blocked</option>
        </select>
      </div>

      {/* Audit Log Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/70 text-slate-400 uppercase font-semibold text-[11px]">
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-4">Operator</th>
                <th className="py-3 px-4">Action</th>
                <th className="py-3 px-4">Target Resource</th>
                <th className="py-3 px-4">Result</th>
                <th className="py-3 px-4">Details / Rationale</th>
                <th className="py-3 px-4 text-right">Inspect</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500 font-sans">
                    No audit records matching query.
                  </td>
                </tr>
              ) : (
                filtered.map(evt => (
                  <tr key={evt.id} className="hover:bg-slate-800/30 transition-colors">
                    <td className="py-3 px-4 text-slate-400 text-[11px]">
                      {evt.timestamp.replace('T', ' ').substring(0, 19)}
                    </td>
                    <td className="py-3 px-4 font-sans">
                      <div className="font-medium text-slate-200">{evt.user}</div>
                      <span className="text-[10px] text-slate-400 font-mono font-semibold">
                        {evt.role}
                      </span>
                    </td>
                    <td className="py-3 px-4 font-bold text-slate-200">
                      {evt.action}
                    </td>
                    <td className="py-3 px-4 text-slate-300 max-w-xs truncate">
                      {evt.resource}
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] font-bold ${
                          evt.result === 'SUCCESS'
                            ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                            : 'bg-rose-500/15 text-rose-400 border border-rose-500/30'
                        }`}
                      >
                        {evt.result === 'SUCCESS' ? (
                          <CheckCircle className="w-3 h-3" />
                        ) : (
                          <XCircle className="w-3 h-3" />
                        )}
                        <span>{evt.result}</span>
                      </span>
                    </td>
                    <td className="py-3 px-4 font-sans text-slate-400 max-w-xs truncate">
                      {evt.reason || '—'}
                    </td>
                    <td className="py-3 px-4 text-right font-sans">
                      <button
                        onClick={() => setSelectedEvent(evt)}
                        className="inline-flex items-center space-x-1 px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs border border-slate-700"
                      >
                        <Eye className="w-3 h-3 text-emerald-400" />
                        <span>JSON</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* JSON Inspector Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-lg p-6 space-y-4 shadow-2xl font-mono">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h3 className="text-sm font-bold text-slate-100">
                Audit Record {selectedEvent.id}
              </h3>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-slate-400 hover:text-slate-200 text-xs font-sans px-2 py-1 rounded bg-slate-800"
              >
                Close
              </button>
            </div>
            <pre className="text-xs bg-slate-950 p-4 rounded-xl border border-slate-800 text-emerald-400 overflow-x-auto max-h-80">
              {JSON.stringify(selectedEvent, null, 2)}
            </pre>
            <div className="text-[11px] text-slate-400 font-sans">
              Request ID: <span className="font-mono text-slate-200">{selectedEvent.request_id}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
