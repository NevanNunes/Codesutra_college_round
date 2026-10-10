import { useState } from 'react';
import './index.css';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { RunSetup } from './components/RunSetup';
import { RunDetail } from './components/RunDetail';
import { setDemoToken } from './api';

type View = 'setup' | 'run';

function App() {
  const [view, setView] = useState<View>('setup');
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [retestRunId, setRetestRunId] = useState<string | null>(null);
  const [sidebarRefresh, setSidebarRefresh] = useState(0);
  const [hasToken, setHasToken] = useState(false);
  const [liveReady] = useState(false);

  const handleTokenChange = (token: string | null) => {
    setDemoToken(token);
    setHasToken(!!token);
  };

  const handleRunCreated = (runId: string) => {
    setSelectedRunId(runId);
    setRetestRunId(null);
    setView('run');
    setSidebarRefresh(n => n + 1);
  };

  const handleSelectRun = (id: string) => {
    setSelectedRunId(id);
    setRetestRunId(null);
    setView('run');
  };

  const handleRetest = (newRunId: string) => {
    setRetestRunId(newRunId);
    setSidebarRefresh(n => n + 1);
  };

  return (
    <div className="app-layout">
      <Header
        onTokenChange={handleTokenChange}
        hasToken={hasToken}
      />

      <div className="main-content">
        <Sidebar
          selectedRunId={selectedRunId}
          onSelectRun={handleSelectRun}
          onNewRun={() => setView('setup')}
          refreshTrigger={sidebarRefresh}
        />

        <main className="content-area" id="main-content" aria-label="Main content">
          {view === 'setup' && (
            <RunSetup
              onRunCreated={handleRunCreated}
              liveReady={liveReady}
            />
          )}

          {view === 'run' && selectedRunId && (
            <RunDetail
              runId={selectedRunId}
              onRetest={handleRetest}
              retestRunId={retestRunId}
            />
          )}

          {view === 'run' && !selectedRunId && (
            <div className="empty-state">
              <span className="empty-state-icon">🔍</span>
              <p>Select a run from the sidebar or start a new one.</p>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

export default App;
