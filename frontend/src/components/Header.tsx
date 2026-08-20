import { Link, useLocation } from 'react-router-dom';

export const Header = () => {
  const location = useLocation();

  const getLinkClass = (path: string) => {
    const isActive = location.pathname === path;
    return isActive
      ? "text-primary text-sm font-bold border-b-2 border-primary py-1 leading-normal"
      : "text-slate-600 dark:text-slate-400 hover:text-primary dark:hover:text-primary text-sm font-medium transition-colors leading-normal";
  };

  return (
    <header className="flex items-center justify-between whitespace-nowrap border-b border-slate-200 dark:border-slate-800 px-6 lg:px-10 py-3 bg-white dark:bg-background-dark sticky top-0 z-50">
      <div className="flex items-center gap-4">
        <div className="size-8 flex items-center justify-center rounded bg-primary">
          <span className="material-symbols-outlined text-white">shield_with_heart</span>
        </div>
        <h2 className="text-slate-900 dark:text-slate-100 text-lg font-bold leading-tight tracking-tight">Vigil SOC</h2>
      </div>

        <nav className="hidden md:flex items-center gap-9">
          <Link to="/" className={getLinkClass("/")}>Dashboard</Link>
          <Link to="/orchestrator" className={getLinkClass("/orchestrator")}>Orchestrator</Link>
          <Link to="/metrics" className={getLinkClass("/metrics")}>Metrics</Link>
        </nav>
    </header>
  );
};
