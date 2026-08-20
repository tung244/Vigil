import { useState } from 'react';
import { Sidebar } from '../components/Sidebar';
import { GraphView } from '../components/GraphView';
import { RightPanel } from '../components/RightPanel';
import { Footer } from '../components/Footer';
import { Header } from '../components/Header';

export default function Orchestrator() {
  const [selectedAgentId, setSelectedAgentId] = useState<string | null>(null);

  return (
    <div className="bg-background-light dark:bg-background-dark text-slate-900 dark:text-slate-100 font-display relative flex h-auto min-h-screen w-full flex-col overflow-x-hidden transition-colors duration-300">
      <Header />

      <main className="flex-1 flex flex-col lg:flex-row h-[calc(100vh-64px)] overflow-hidden">
        <Sidebar selectedAgentId={selectedAgentId} onSelectAgent={setSelectedAgentId} />
        <GraphView />
        <RightPanel selectedAgentId={selectedAgentId} onClearSelection={() => setSelectedAgentId(null)} />
      </main>

      <Footer />
    </div>
  );
}
