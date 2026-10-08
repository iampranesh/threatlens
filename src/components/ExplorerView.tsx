import React from 'react';
import {
  Search,
  Filter,
  SlidersHorizontal,
  Eye,
  Plus,
  Shield,
  ShieldAlert,
  ArrowUpDown,
  CheckCircle2,
  AlertTriangle,
  RotateCcw
} from 'lucide-react';
import { Indicator } from '../server/types.ts';

interface ExplorerViewProps {
  indicators: Indicator[];
  onSelectIndicator: (ind: Indicator) => void;
  onOpenNewIndicatorModal: () => void;
  initialFilter?: string;
}

export const ExplorerView: React.FC<ExplorerViewProps> = ({
  indicators,
  onSelectIndicator,
  onOpenNewIndicatorModal,
  initialFilter
}) => {
  const [search, setSearch] = React.useState('');
  const [labelFilter, setLabelFilter] = React.useState<string>(
    initialFilter === 'prioritized' ? 'PRIORITIZED' : 'ALL'
  );
  const [typeFilter, setTypeFilter] = React.useState('ALL');
  const [sourceFilter, setSourceFilter] = React.useState('ALL');
  const [currentPage, setCurrentPage] = React.useState(1);
  const itemsPerPage = 20;

  // Extract unique sources and types
  const sources = React.useMemo(() => {
    const s = new Set<string>();
    indicators.forEach(i => i.source && s.add(i.source));
    return Array.from(s).sort();
  }, [indicators]);

  const filtered = React.useMemo(() => {
    return indicators.filter(item => {
      // Search
      if (search.trim()) {
        const q = search.toLowerCase();
        const match =
          item.indicator.toLowerCase().includes(q) ||
          (item.malware_family && item.malware_family.toLowerCase().includes(q)) ||
          (item.threat_actor && item.threat_actor.toLowerCase().includes(q)) ||
          (item.cve && item.cve.toLowerCase().includes(q)) ||
          (item.matched_asset && item.matched_asset.toLowerCase().includes(q));
        if (!match) return false;
      }

      // Classification Filter
      if (labelFilter === 'PRIORITIZED') {
        if (!item.is_prioritized) return false;
      } else if (labelFilter === 'SUPPRESSED') {
        if (item.is_prioritized) return false;
      } else if (labelFilter !== 'ALL') {
        if (item.label !== labelFilter) return false;
      }

      // Type Filter
      if (typeFilter !== 'ALL' && item.type !== typeFilter) {
        return false;
      }

      // Source Filter
      if (sourceFilter !== 'ALL' && item.source !== sourceFilter) {
        return false;
      }

      return true;
    });
  }, [indicators, search, labelFilter, typeFilter, sourceFilter]);

  const totalPages = Math.ceil(filtered.length / itemsPerPage);
  const paginated = React.useMemo(() => {
    const start = (currentPage - 1) * itemsPerPage;
    return filtered.slice(start, start + itemsPerPage);
  }, [filtered, currentPage]);

  const resetFilters = () => {
    setSearch('');
    setLabelFilter('ALL');
    setTypeFilter('ALL');
    setSourceFilter('ALL');
    setCurrentPage(1);
  };

  const getLabelBadge = (label?: string) => {
    switch (label) {
      case 'CRITICAL':
        return 'bg-rose-500/15 text-rose-400 border border-rose-500/30';
      case 'HIGH':
        return 'bg-amber-500/15 text-amber-400 border border-amber-500/30';
      case 'MEDIUM':
        return 'bg-yellow-500/15 text-yellow-400 border border-yellow-500/30';
      case 'LOW':
        return 'bg-blue-500/15 text-blue-400 border border-blue-500/30';
      case 'IRRELEVANT':
      default:
        return 'bg-slate-800 text-slate-400 border border-slate-700';
    }
  };

  return (
    <div className="space-y-4">
      {/* Header and Controls */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 p-4 rounded-xl">
        <div>
          <h2 className="text-lg font-bold text-slate-100 flex items-center space-x-2">
            <span>Threat Indicator Explorer</span>
            <span className="text-xs font-mono font-medium px-2 py-0.5 rounded bg-slate-800 text-slate-300">
              {filtered.length} of {indicators.length} IOCs
            </span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Filter, inspect evidence chains, or test custom indicators through the local-relevance scorer.
          </p>
        </div>

        <button
          onClick={onOpenNewIndicatorModal}
          className="inline-flex items-center space-x-2 px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-semibold text-xs transition-colors shadow-md shadow-emerald-950"
        >
          <Plus className="w-4 h-4" />
          <span>Ingest / Test Indicator</span>
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="bg-slate-900/80 border border-slate-800 p-4 rounded-xl space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
          {/* Search Box */}
          <div className="md:col-span-1 relative">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search IOC, Actor, CVE, Asset..."
              value={search}
              onChange={e => { setSearch(e.target.value); setCurrentPage(1); }}
              className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
          </div>

          {/* Classification Filter */}
          <div>
            <select
              value={labelFilter}
              onChange={e => { setLabelFilter(e.target.value); setCurrentPage(1); }}
              className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            >
              <option value="ALL">All Classifications</option>
              <option value="PRIORITIZED">Prioritized Queue (Score ≥ 60)</option>
              <option value="SUPPRESSED">Suppressed Noise (Score &lt; 60)</option>
              <option value="CRITICAL">Critical (80–100)</option>
              <option value="HIGH">High (60–79)</option>
              <option value="MEDIUM">Medium (40–59)</option>
              <option value="LOW">Low (20–39)</option>
              <option value="IRRELEVANT">Irrelevant (0–19)</option>
            </select>
          </div>

          {/* Type Filter */}
          <div>
            <select
              value={typeFilter}
              onChange={e => { setTypeFilter(e.target.value); setCurrentPage(1); }}
              className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            >
              <option value="ALL">All Indicator Types</option>
              <option value="ipv4">IPv4 Addresses</option>
              <option value="domain">Domain Names</option>
              <option value="url">URLs</option>
              <option value="sha256">SHA256 Hashes</option>
            </select>
          </div>

          {/* Feed Source Filter */}
          <div className="flex items-center space-x-2">
            <select
              value={sourceFilter}
              onChange={e => { setSourceFilter(e.target.value); setCurrentPage(1); }}
              className="flex-1 px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-emerald-500"
            >
              <option value="ALL">All Threat Sources</option>
              {sources.map(src => (
                <option key={src} value={src}>{src}</option>
              ))}
            </select>

            {(search || labelFilter !== 'ALL' || typeFilter !== 'ALL' || sourceFilter !== 'ALL') && (
              <button
                onClick={resetFilters}
                title="Reset Filters"
                className="p-1.5 text-slate-400 hover:text-slate-200 bg-slate-800 rounded-lg border border-slate-700"
              >
                <RotateCcw className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Indicator Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/70 text-slate-400 uppercase font-semibold text-[11px]">
                <th className="py-3 px-4">Indicator</th>
                <th className="py-3 px-4">Feed Source</th>
                <th className="py-3 px-4">ThreatLens Score</th>
                <th className="py-3 px-4">Classification</th>
                <th className="py-3 px-4">Baseline Comparison</th>
                <th className="py-3 px-4">Matched Asset</th>
                <th className="py-3 px-4">Evidence Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
              {paginated.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-sans">
                    No threat indicators match the active filters.
                  </td>
                </tr>
              ) : (
                paginated.map(ind => (
                  <tr key={ind.indicator_id} className="hover:bg-slate-800/40 transition-colors">
                    {/* Indicator Column */}
                    <td className="py-3 px-4 max-w-xs truncate">
                      <div className="font-semibold text-slate-100">{ind.indicator}</div>
                      <div className="text-[10px] text-slate-400 capitalize font-sans">
                        {ind.type} {ind.cve ? `• ${ind.cve}` : ''}
                      </div>
                    </td>

                    {/* Source Column */}
                    <td className="py-3 px-4 font-sans">
                      <div className="text-slate-300">{ind.source}</div>
                      <div className="text-[10px] text-slate-400">Conf: {ind.confidence}%</div>
                    </td>

                    {/* ThreatLens Score */}
                    <td className="py-3 px-4">
                      <div className="flex items-center space-x-2">
                        <span className="font-bold text-slate-100">{ind.score}</span>
                        <div className="w-14 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                          <div
                            className={`h-1.5 rounded-full ${
                              ind.score && ind.score >= 80
                                ? 'bg-rose-500'
                                : ind.score && ind.score >= 60
                                ? 'bg-amber-500'
                                : ind.score && ind.score >= 40
                                ? 'bg-yellow-500'
                                : 'bg-slate-600'
                            }`}
                            style={{ width: `${ind.score}%` }}
                          />
                        </div>
                      </div>
                    </td>

                    {/* Classification Label */}
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${getLabelBadge(ind.label)}`}>
                        {ind.label}
                      </span>
                    </td>

                    {/* Baseline vs ThreatLens */}
                    <td className="py-3 px-4 font-sans text-[11px]">
                      {ind.baseline_score !== undefined && (
                        <div>
                          <span className="text-slate-400">Raw Feed: </span>
                          <span className={ind.baseline_prioritized ? 'text-rose-400 font-medium' : 'text-slate-400'}>
                            {ind.baseline_score} ({ind.baseline_prioritized ? 'ALERT' : 'PASS'})
                          </span>
                        </div>
                      )}
                    </td>

                    {/* Matched Asset */}
                    <td className="py-3 px-4 font-sans text-xs">
                      {ind.matched_asset && ind.matched_asset !== 'NONE' ? (
                        <span className="px-2 py-0.5 rounded bg-sky-950/60 border border-sky-800 text-sky-400 font-mono text-[10px]">
                          {ind.matched_asset}
                        </span>
                      ) : (
                        <span className="text-slate-500 text-xs">Unmatched</span>
                      )}
                    </td>

                    {/* Evidence Status */}
                    <td className="py-3 px-4 font-sans text-xs">
                      {ind.evidence && ind.evidence.length > 0 ? (
                        <div className="flex items-center space-x-1 text-emerald-400">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>{ind.evidence.length} signals</span>
                        </div>
                      ) : (
                        <span className="text-slate-500">Zero evidence</span>
                      )}
                    </td>

                    {/* Action */}
                    <td className="py-3 px-4 text-right font-sans">
                      <button
                        onClick={() => onSelectIndicator(ind)}
                        className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs transition-colors"
                      >
                        <Eye className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Inspect</span>
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        {totalPages > 1 && (
          <div className="p-3 bg-slate-950/60 border-t border-slate-800 flex items-center justify-between text-xs text-slate-400">
            <div>
              Showing {(currentPage - 1) * itemsPerPage + 1} to{' '}
              {Math.min(currentPage * itemsPerPage, filtered.length)} of {filtered.length} entries
            </div>
            <div className="flex items-center space-x-2">
              <button
                disabled={currentPage === 1}
                onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none text-slate-300"
              >
                Previous
              </button>
              <span className="text-slate-300 font-mono font-medium">
                Page {currentPage} of {totalPages}
              </span>
              <button
                disabled={currentPage === totalPages}
                onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:pointer-events-none text-slate-300"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
