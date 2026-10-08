import React from 'react';
import { Header } from './components/Header.tsx';
import { DashboardView } from './components/DashboardView.tsx';
import { ExplorerView } from './components/ExplorerView.tsx';
import { ExplainModal } from './components/ExplainModal.tsx';
import { BenchmarkView } from './components/BenchmarkView.tsx';
import { GovernanceView } from './components/GovernanceView.tsx';
import { AuditView } from './components/AuditView.tsx';
import { SecuritySuiteView } from './components/SecuritySuiteView.tsx';
import { ContainmentModal } from './components/ContainmentModal.tsx';
import { NewIndicatorModal } from './components/NewIndicatorModal.tsx';
import { Indicator, User } from './server/types.ts';

export default function App() {
  const [currentUser, setCurrentUser] = React.useState<User>({
    id: 'USR-01',
    name: 'Sarah Chen',
    email: 'sarah.chen@threatlens.corp',
    role: 'ANALYST',
    avatar: 'SC'
  });

  const [activeTab, setActiveTab] = React.useState('dashboard');
  const [metrics, setMetrics] = React.useState<any>(null);
  const [indicators, setIndicators] = React.useState<Indicator[]>([]);
  const [highPriority, setHighPriority] = React.useState<Indicator[]>([]);
  const [selectedIndicator, setSelectedIndicator] = React.useState<Indicator | null>(null);
  const [containmentTarget, setContainmentTarget] = React.useState<Indicator | null>(null);
  const [newIndicatorOpen, setNewIndicatorOpen] = React.useState(false);
  const [explorerFilter, setExplorerFilter] = React.useState<string | undefined>();
  const [loading, setLoading] = React.useState(true);

  const fetchInitialData = React.useCallback(async () => {
    try {
      const [authRes, metricsRes, indRes, highRes] = await Promise.all([
        fetch('/api/auth/me').then(r => r.json()),
        fetch('/api/metrics').then(r => r.json()),
        fetch('/api/indicators?limit=1000').then(r => r.json()),
        fetch('/api/high-priority').then(r => r.json())
      ]);

      if (authRes.user) setCurrentUser(authRes.user);
      setMetrics(metricsRes);
      setIndicators(indRes.indicators || []);
      setHighPriority(highRes.indicators || []);
    } catch (err) {
      console.error('Error fetching initial ThreatLens data:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    fetchInitialData();
  }, [fetchInitialData]);

  const handleSwitchUser = async (roleKey: string) => {
    try {
      const res = await fetch('/api/auth/switch-role', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ roleKey })
      });
      const data = await res.json();
      if (data.user) {
        setCurrentUser(data.user);
      }
    } catch (err) {
      console.error('Failed to switch user role:', err);
    }
  };

  const handleNavigateToExplorer = (filter?: string) => {
    setExplorerFilter(filter);
    setActiveTab('explorer');
  };

  const handleIndicatorCreated = (newInd: Indicator) => {
    setIndicators(prev => [newInd, ...prev]);
    if (newInd.is_prioritized) {
      setHighPriority(prev => [newInd, ...prev]);
    }
    fetchInitialData();
    setSelectedIndicator(newInd);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-emerald-500 selection:text-slate-950">
      {/* Top Header */}
      <Header
        currentUser={currentUser}
        onSwitchUser={handleSwitchUser}
        activeTab={activeTab}
        onTabChange={tab => {
          setExplorerFilter(undefined);
          setActiveTab(tab);
        }}
        metrics={metrics}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {loading ? (
          <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-3">
            <div className="w-10 h-10 border-2 border-emerald-500 border-t-transparent rounded-full animate-spin" />
            <span className="text-xs text-slate-400 font-mono">
              Loading ThreatLens In-Memory Datastore &amp; Engine...
            </span>
          </div>
        ) : (
          <>
            {activeTab === 'dashboard' && (
              <DashboardView
                metrics={metrics}
                highPriorityIndicators={highPriority}
                onSelectIndicator={setSelectedIndicator}
                onNavigateToExplorer={handleNavigateToExplorer}
              />
            )}

            {activeTab === 'explorer' && (
              <ExplorerView
                indicators={indicators}
                onSelectIndicator={setSelectedIndicator}
                onOpenNewIndicatorModal={() => setNewIndicatorOpen(true)}
                initialFilter={explorerFilter}
              />
            )}

            {activeTab === 'benchmark' && (
              <BenchmarkView metrics={metrics} />
            )}

            {activeTab === 'governance' && (
              <GovernanceView
                currentUser={currentUser}
                onRefreshData={fetchInitialData}
              />
            )}

            {activeTab === 'audit' && (
              <AuditView />
            )}

            {activeTab === 'security' && (
              <SecuritySuiteView
                currentUser={currentUser}
                onRefreshAll={fetchInitialData}
              />
            )}
          </>
        )}
      </main>

      {/* Indicator Detail & Explainability Modal */}
      {selectedIndicator && (
        <ExplainModal
          indicator={selectedIndicator}
          onClose={() => setSelectedIndicator(null)}
          onProposeAction={ind => {
            setSelectedIndicator(null);
            setContainmentTarget(ind);
          }}
        />
      )}

      {/* Containment Action Proposal Modal */}
      {containmentTarget && (
        <ContainmentModal
          indicator={containmentTarget}
          currentUser={currentUser}
          onClose={() => setContainmentTarget(null)}
          onSuccess={() => {
            fetchInitialData();
            setActiveTab('audit');
          }}
        />
      )}

      {/* New Indicator Ingestion Modal */}
      {newIndicatorOpen && (
        <NewIndicatorModal
          onClose={() => setNewIndicatorOpen(false)}
          onIndicatorCreated={handleIndicatorCreated}
        />
      )}

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-4 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div>
            ThreatLens™ Explainable Local-Relevance Platform • RFC 5737 Synthetic Testnet Pilot
          </div>
          <div className="font-mono text-[11px] text-slate-400">
            Active Role: <span className="text-emerald-400 font-semibold">{currentUser.role}</span> ({currentUser.name})
          </div>
        </div>
      </footer>
    </div>
  );
}
