import type { MitreStats, MitreTechnique } from '../services/api';

// ─── MITRE ATT&CK heatmap (Wazuh-style grid) ────────────────────────────────
// Columns = tactics (kill-chain order from the API), cells = techniques,
// color intensity scales with the technique's hit count.

const heatClass = (count: number, max: number): string => {
  const ratio = count / max;
  if (ratio > 0.75) return 'bg-red-600 text-white border-red-500';
  if (ratio > 0.5) return 'bg-orange-500 text-white border-orange-400';
  if (ratio > 0.25) return 'bg-sky-700 text-sky-50 border-sky-600';
  return 'bg-sky-950 text-sky-300 border-sky-800';
};

export const MitreHeatmap = ({ data }: { data: MitreStats | null }) => {
  if (!data || data.techniques.length === 0) {
    return (
      <div className="text-sm text-slate-500 py-8 font-medium italic text-center">
        No MITRE ATT&CK techniques recorded yet.
      </div>
    );
  }

  const max = Math.max(...data.techniques.map((t) => t.count), 1);

  const byTactic = new Map<string, MitreTechnique[]>();
  for (const t of data.techniques) {
    const list = byTactic.get(t.tactic) ?? [];
    list.push(t);
    byTactic.set(t.tactic, list);
  }

  // Column order follows the API's kill-chain-sorted tactic list; append any
  // tactic present in techniques but missing from the list (defensive).
  const tactics = [
    ...data.tactics.filter((t) => byTactic.has(t)),
    ...[...byTactic.keys()].filter((t) => !data.tactics.includes(t)),
  ];

  return (
    <div>
      <div className="overflow-x-auto pb-2">
        <div className="flex gap-2 min-w-max">
          {tactics.map((tactic) => {
            const cells = [...(byTactic.get(tactic) ?? [])].sort((a, b) => b.count - a.count);
            const total = cells.reduce((acc, c) => acc + c.count, 0);
            return (
              <div key={tactic} className="flex flex-col gap-1 w-[96px] flex-shrink-0">
                <div className="h-9 flex flex-col justify-end" title={tactic}>
                  <span className="text-[9px] font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 leading-tight line-clamp-2">
                    {tactic}
                  </span>
                  <span className="text-[9px] font-mono text-slate-400 dark:text-slate-500">{total} hits</span>
                </div>
                {cells.map((cell) => (
                  <div
                    key={cell.techniqueId}
                    title={`${cell.techniqueId} · ${tactic} — ${cell.count} report${cell.count === 1 ? '' : 's'}`}
                    className={`rounded border px-1.5 py-1 flex items-center justify-between gap-1 cursor-default transition-transform hover:scale-105 ${heatClass(cell.count, max)}`}
                  >
                    <span className="font-mono text-[10px] font-bold leading-none">{cell.techniqueId}</span>
                    <span className="font-mono text-[10px] font-bold leading-none opacity-80">{cell.count}</span>
                  </div>
                ))}
              </div>
            );
          })}
        </div>
      </div>
      {/* Intensity legend */}
      <div className="flex items-center gap-2 mt-3">
        <span className="text-[9px] font-bold uppercase tracking-wider text-slate-400">Low</span>
        <span className="w-6 h-2 rounded-sm bg-sky-950 border border-sky-800"></span>
        <span className="w-6 h-2 rounded-sm bg-sky-700"></span>
        <span className="w-6 h-2 rounded-sm bg-orange-500"></span>
        <span className="w-6 h-2 rounded-sm bg-red-600"></span>
        <span className="text-[9px] font-bold uppercase tracking-wider text-slate-400">High</span>
        <span className="ml-auto text-[9px] font-mono text-slate-500">max {max} / technique</span>
      </div>
    </div>
  );
};
