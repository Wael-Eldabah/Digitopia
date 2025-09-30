// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useContext, useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import AuthContext from '../context/AuthContext.jsx';

export default function LoginPage({ onLogin, isSubmitting = false }) {
  const [form, setForm] = useState({ email: '', password: '' });
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const location = useLocation();
  const from = location.state?.from?.pathname || '/';
  const { isAuthenticated } = useContext(AuthContext);

  useEffect(() => {
    if (isAuthenticated) {
      navigate(from, { replace: true });
    }
  }, [isAuthenticated, from, navigate]);

  const handleChange = (event) => {
    const { name, value } = event.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!form.email || !form.password) {
      setError('Email and password are required.');
      return;
    }
    try {
      setError('');
      await onLogin({ email: form.email, password: form.password });
    } catch (err) {
      const message = err?.response?.data?.detail?.message || 'Unable to sign in with the provided credentials.';
      setError(message);
    }
  };

  return (
    <div className="min-h-screen bg-[#0b1220] flex items-center justify-center px-4">
      <div className="max-w-md w-full bg-[#111a2e] border border-slate-800/80 rounded-3xl shadow-[0_30px_60px_rgba(15,23,42,0.45)] p-10 text-slate-200 space-y-8">
        <div className="flex flex-col items-center gap-4">
          <div className="w-20 h-20 rounded-full bg-gradient-to-br from-emerald-400 via-cyan-400 to-blue-400 flex items-center justify-center shadow-[0_20px_35px_rgba(34,197,94,0.2)]">
            <svg width="44" height="44" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.3" className="text-slate-950">
              <path d="M12 2 3 6v6c0 5 3.8 9.7 9 10 5.2-.3 9-5 9-10V6l-9-4Z" fill="currentColor" opacity="0.12" />
              <path d="m12 22 9-6V6l-9 4m0 12-9-6V6l9 4" />
              <path d="M12 10v12" />
            </svg>
          </div>
          <div className="text-center space-y-1">
            <h1 className="text-3xl font-semibold tracking-tight">EyeGuard</h1>
            <p className="text-sm text-slate-400">AI-Powered Cybersecurity Monitoring</p>
          </div>
        </div>
        <form onSubmit={handleSubmit} className="space-y-5">
          <div className="space-y-2">
            <label htmlFor="email" className="text-xs uppercase tracking-wide text-slate-400">Email Address</label>
            <div className="relative">
              <span className="absolute inset-y-0 left-3 flex items-center text-slate-500">
                <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.6" viewBox="0 0 24 24">
                  <path d="M4 6h16v12H4z" />
                  <path d="m4 6 8 6 8-6" />
                </svg>
              </span>
              <input
                id="email"
                name="email"
                type="email"
                value={form.email}
                onChange={handleChange}
                className="w-full bg-[#0d1524] border border-slate-800 focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/40 rounded-xl py-3 pl-11 pr-3 text-sm transition"
                placeholder="you@eyeguard.com"
                required
              />
            </div>
          </div>
          <div className="space-y-2">
            <label htmlFor="password" className="text-xs uppercase tracking-wide text-slate-400">Password</label>
            <div className="relative">
              <span className="absolute inset-y-0 left-3 flex items-center text-slate-500">
                <svg width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.6" viewBox="0 0 24 24">
                  <rect x="7" y="10" width="10" height="10" rx="2" />
                  <path d="M9 10V7a3 3 0 0 1 6 0v3" />
                </svg>
              </span>
              <input
                id="password"
                name="password"
                type="password"
                value={form.password}
                onChange={handleChange}
                className="w-full bg-[#0d1524] border border-slate-800 focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/40 rounded-xl py-3 pl-11 pr-3 text-sm transition"
                placeholder="Enter password"
                required
              />
            </div>
          </div>
          {error && (
            <p className="text-xs text-rose-400 bg-rose-500/10 border border-rose-500/30 rounded-lg px-3 py-2">
              {error}
            </p>
          )}
          <div className="flex items-center justify-between text-xs text-slate-400">
            <button
              type="button"
              className="text-emerald-400 hover:text-emerald-300 transition"
              onClick={() => navigate('/forgot')}
            >
              Forgot Password?
            </button>
            <span>
              Need access?{' '}
              <button
                type="button"
                className="text-sky-400 hover:text-sky-300 transition"
                onClick={() => navigate('/signup')}
              >
                Sign Up
              </button>
            </span>
          </div>
          <button
            type="submit"
            disabled={isSubmitting}
            className="w-full py-3 rounded-xl bg-gradient-to-r from-emerald-500 to-green-500 hover:from-emerald-400 hover:to-green-400 text-slate-950 font-semibold shadow-lg shadow-emerald-500/20 transition disabled:opacity-60"
          >
            {isSubmitting ? 'Signing in...' : 'Login'}
          </button>
        </form>
      </div>
    </div>
  );
}