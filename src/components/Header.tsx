import React from 'react';
import {
  ShieldAlert,
  Radio,
  UserCheck,
  ChevronDown,
  Activity,
  Layers,
  Sliders,
  FileText,
  Lock,
  Filter
} from 'lucide-react';
import { User } from '../server/types.ts';

interface HeaderProps {
  currentUser: User;
  onSwitchUser: (roleKey: string) => void;
  activeTab: string;
  onTabChange: (tab: string) => void;
  metrics: any;
}

export const Header: React.FC<HeaderProps> = ({
  currentUser,
  onSwitchUser,
  activeTab,
  onTabChange,
  metrics
}) => {
  const [dropdownOpen, setDropdownOpen] = React.useState(false);

  const roleColors: Record<string, string> = {
    ANALYST: 'bg-sky-950 text-sky-400 border-sky-800',
    REVIEWER: 'bg-amber-950 text-amber-400 border-amber-800',
    ADMIN: 'bg-purple-950 text-purple-400 border-purple-800'
  };

  const navItems = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: Activity },
    { id: 'explorer', label: 'Indicator Explorer', icon: Filter },
    { id: 'benchmark', label: 'Benchmark & Validation', icon: Layers },
    { id: 'governance', label: 'Governance & Rollback', icon: Sliders },
    { id: 'audit', label: 'Audit Trail', icon: FileText },
    { id: 'security', label: 'Security & Edge Tests', icon: Lock }
  ];

  return (
    <header className="bg-slate-950 border-b border-slate-800 sticky top-0 z-40">
      {/* Top Bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo & Platform Name */}
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-lg bg-emerald-950 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shadow-lg shadow-emerald-950/50">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-xl font-bold tracking-tight text-slate-100">ThreatLens</span>
                <span className="px-2 py-0.5 text-xs font-semibold rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                  v1.0.0
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Explainable Local-Relevance Threat Intelligence Prioritization
              </p>
            </div>
          </div>

          {/* Quick Metrics Bar */}
          {metrics && (
            <div className="hidden lg:flex items-center space-x-6 text-xs text-slate-300 bg-slate-900/80 px-4 py-2 rounded-lg border border-slate-800">
              <div className="flex items-center space-x-2">
                <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
                <span className="text-slate-400">Ingested:</span>
                <span className="font-semibold text-slate-100">{metrics.total_indicators || 1000} IOCs</span>
              </div>
              <div className="h-3 w-px bg-slate-700" />
              <div>
                <span className="text-slate-400">Actionable:</span>{' '}
                <span className="font-semibold text-rose-400">{metrics.threatlens?.total_prioritized || 145}</span>
              </div>
              <div className="h-3 w-px bg-slate-700" />
              <div>
                <span className="text-slate-400">Suppressed Noise:</span>{' '}
                <span className="font-semibold text-emerald-400">{metrics.threatlens?.total_suppressed || 855}</span>
              </div>
              <div className="h-3 w-px bg-slate-700" />
              <div>
                <span className="text-slate-400">Workload Saved:</span>{' '}
                <span className="font-semibold text-sky-400">+{metrics.threatlens?.workload_reduction || 79.8}%</span>
              </div>
            </div>
          )}

          {/* User & Role Switcher */}
          <div className="relative">
            <button
              onClick={() => setDropdownOpen(!dropdownOpen)}
              className="flex items-center space-x-3 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-850 border border-slate-800 text-left transition-colors"
            >
              <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-xs font-semibold text-slate-300">
                {currentUser.avatar}
              </div>
              <div className="hidden sm:block">
                <div className="text-xs font-medium text-slate-200">{currentUser.name}</div>
                <div className="flex items-center space-x-1">
                  <span className={`text-[10px] px-1.5 py-0.2 rounded border font-mono font-semibold ${roleColors[currentUser.role] || ''}`}>
                    {currentUser.role}
                  </span>
                </div>
              </div>
              <ChevronDown className="w-4 h-4 text-slate-400" />
            </button>

            {/* Dropdown Menu */}
            {dropdownOpen && (
              <div className="absolute right-0 mt-2 w-64 rounded-xl bg-slate-900 border border-slate-800 shadow-2xl py-2 z-50">
                <div className="px-3 py-1.5 text-[11px] font-semibold text-slate-400 uppercase tracking-wider border-b border-slate-800">
                  Switch Active Role (RBAC Simulation)
                </div>
                <button
                  onClick={() => { onSwitchUser('analyst'); setDropdownOpen(false); }}
                  className={`w-full text-left px-3 py-2 text-xs flex items-center justify-between hover:bg-slate-800/80 transition-colors ${
                    currentUser.role === 'ANALYST' ? 'bg-sky-500/10 text-sky-300' : 'text-slate-300'
                  }`}
                >
                  <div>
                    <div className="font-medium">Sarah Chen</div>
                    <div className="text-[10px] text-slate-400">Read & Investigate Only</div>
                  </div>
                  <span className="text-[10px] px-1.5 py-0.5 rounded border border-sky-800 bg-sky-950 text-sky-400 font-mono">
                    ANALYST
                  </span>
                </button>
                <button
                  onClick={() => { onSwitchUser('reviewer'); setDropdownOpen(false); }}
                  className={`w-full text-left px-3 py-2 text-xs flex items-center justify-between hover:bg-slate-800/80 transition-colors ${
                    currentUser.role === 'REVIEWER' ? 'bg-amber-500/10 text-amber-300' : 'text-slate-300'
                  }`}
                >
                  <div>
                    <div className="font-medium">Marcus Vance</div>
                    <div className="text-[10px] text-slate-400">Review & Approve Actions</div>
                  </div>
                  <span className="text-[10px] px-1.5 py-0.5 rounded border border-amber-800 bg-amber-950 text-amber-400 font-mono">
                    REVIEWER
                  </span>
                </button>
                <button
                  onClick={() => { onSwitchUser('admin'); setDropdownOpen(false); }}
                  className={`w-full text-left px-3 py-2 text-xs flex items-center justify-between hover:bg-slate-800/80 transition-colors ${
                    currentUser.role === 'ADMIN' ? 'bg-purple-500/10 text-purple-300' : 'text-slate-300'
                  }`}
                >
                  <div>
                    <div className="font-medium">Elena Rostova</div>
                    <div className="text-[10px] text-slate-400">Manage Config & Rollback</div>
                  </div>
                  <span className="text-[10px] px-1.5 py-0.5 rounded border border-purple-800 bg-purple-950 text-purple-400 font-mono">
                    ADMIN
                  </span>
                </button>
              </div>
            )}
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex space-x-1 overflow-x-auto py-2 border-t border-slate-900/60 no-scrollbar">
          {navItems.map(item => {
            const Icon = item.icon;
            const active = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onTabChange(item.id)}
                className={`flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-all ${
                  active
                    ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                }`}
              >
                <Icon className={`w-3.5 h-3.5 ${active ? 'text-emerald-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>
    </header>
  );
};
