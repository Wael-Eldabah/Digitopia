// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

export default function ForgotPasswordPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setToken('');
    setSubmitting(true);
    try {
      const { data } = await axios.post('/api/v1/auth/forgot', { email });
      setToken(data.reset_token);
    } catch (err) {
      const message = err?.response?.data?.detail?.message || 'Password reset failed for this email.';
      setError(message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0b1220] flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-lg bg-[#111a2e] border border-slate-800/80 rounded-3xl shadow-[0_30px_60px_rgba(15,23,42,0.45)] p-10 space-y-6 text-slate-200">
        <div className="space-y-1">
          <h1 className="text-3xl font-semibold tracking-tight">Reset Access</h1>
          <p className="text-sm text-slate-400">Submit your email to receive a simulated reset token.</p>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="email" className="text-xs uppercase tracking-wide text-slate-400">Email Address</label>
            <input
              id="email"
              name="email"
              type="email"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
              className="w-full bg-[#0d1524] border border-slate-800 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30 rounded-xl px-3 py-2 text-sm"
              placeholder="you@eyeguard.com"
              required
            />
          </div>
          {error && (
            <p className="text-xs text-rose-400 bg-rose-500/10 border border-rose-500/30 rounded-lg px-3 py-2">{error}</p>
          )}
          {token && (
            <div className="space-y-2">
              <p className="text-xs text-slate-400">Reset token (use in simulation only):</p>
              <code className="block text-sm bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-emerald-300 break-all">{token}</code>
            </div>
          )}
          <button
            type="submit"
            disabled={submitting}
            className="w-full py-3 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-500 hover:from-sky-400 hover:to-indigo-400 text-slate-950 font-semibold shadow-lg shadow-sky-500/20 transition disabled:opacity-60"
          >
            {submitting ? 'Submitting...' : 'Send Reset Token'}
          </button>
        </form>
        <button
          type="button"
          className="w-full text-sm text-slate-400 hover:text-slate-200 transition"
          onClick={() => navigate('/login')}
        >
          Back to Login
        </button>
      </div>
    </div>
  );
}