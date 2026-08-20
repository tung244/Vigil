import { useState } from 'react';
import type { FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import { login } from '../services/api';

/**
 * SOC login gate. The API only has one user (config-driven), so this is a
 * single credentials card — no registration, no password reset flow.
 */
export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    const ok = await login(username.trim(), password);
    setBusy(false);
    if (ok) {
      navigate('/');
    } else {
      setError('Invalid credentials — check Auth:AdminUser / Auth:AdminPassword in the API config.');
    }
  };

  return (
    <div className="min-h-screen bg-[#0b0f14] flex items-center justify-center px-4">
      <div className="w-full max-w-sm">
        <div className="flex items-center gap-3 mb-8 justify-center">
          <span className="material-symbols-outlined text-emerald-400 text-3xl">shield_lock</span>
          <div>
            <h1 className="text-slate-100 font-semibold tracking-wide">VIGIL SOC</h1>
            <p className="text-xs text-slate-500 font-mono">autonomous incident response</p>
          </div>
        </div>

        <form
          onSubmit={onSubmit}
          className="bg-[#11161d] border border-slate-800 rounded-lg p-6 space-y-4 shadow-xl"
        >
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1.5" htmlFor="username">
              OPERATOR ID
            </label>
            <input
              id="username"
              type="text"
              autoComplete="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full bg-[#0b0f14] border border-slate-700 rounded px-3 py-2 text-sm text-slate-200
                         focus:outline-none focus:border-emerald-500 font-mono"
              required
            />
          </div>
          <div>
            <label className="block text-xs font-mono text-slate-400 mb-1.5" htmlFor="password">
              PASSPHRASE
            </label>
            <input
              id="password"
              type="password"
              autoComplete="current-password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full bg-[#0b0f14] border border-slate-700 rounded px-3 py-2 text-sm text-slate-200
                         focus:outline-none focus:border-emerald-500 font-mono"
              required
            />
          </div>

          {error && (
            <p className="text-xs text-red-400 font-mono border border-red-900/50 bg-red-950/30 rounded px-3 py-2">
              {error}
            </p>
          )}

          <button
            type="submit"
            disabled={busy}
            className="w-full bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-sm
                       font-medium rounded py-2 transition-colors"
          >
            {busy ? 'Authenticating…' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  );
}
