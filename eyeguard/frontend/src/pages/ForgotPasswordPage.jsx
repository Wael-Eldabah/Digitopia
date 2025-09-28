// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

export default function ForgotPasswordPage() {
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [token, setToken] = useState('');
  const [tokenInput, setTokenInput] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [step, setStep] = useState('request');
  const [sentTo, setSentTo] = useState('');
  const [error, setError] = useState('');
  const [confirmError, setConfirmError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [successMessage, setSuccessMessage] = useState('');

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setConfirmError('');
    setSuccessMessage('');
    setSubmitting(true);
    try {
      const { data } = await axios.post('/api/v1/auth/forgot', { email });
      setToken(data.reset_token);
      setSentTo(data.sent_to || email);
      setStep('confirm');
    } catch (err) {
      const message = err?.response?.data?.detail?.message || 'Password reset failed for this email.';
      setError(message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleConfirmReset = async (event) => {
    event.preventDefault();
    if (!tokenInput.trim() || !newPassword.trim()) {
      setConfirmError('Enter the token and a new password.');
      return;
    }
    setConfirmError('');
    setSuccessMessage('');
    setConfirming(true);
    try {
      await axios.post('/api/v1/auth/reset', {
        email,
        token: tokenInput.trim(),
        new_password: newPassword,
      });
      setSuccessMessage('Password updated. You can now sign in.');
      setTimeout(() => navigate('/login'), 1800);
    } catch (err) {
      const message = err?.response?.data?.detail?.message || 'Token validation failed. Please try again.';
      setConfirmError(message);
    } finally {
      setConfirming(false);
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
              disabled={step === 'confirm'}
            />
          </div>
          {error && (
            <p className="text-xs text-rose-400 bg-rose-500/10 border border-rose-500/30 rounded-lg px-3 py-2">{error}</p>
          )}
          {step === 'request' && (
            <button
              type="submit"
              disabled={submitting}
              className="w-full py-3 rounded-xl bg-gradient-to-r from-sky-500 to-indigo-500 hover:from-sky-400 hover:to-indigo-400 text-slate-950 font-semibold shadow-lg shadow-sky-500/20 transition disabled:opacity-60"
            >
              {submitting ? 'Submitting...' : 'Send Reset Token'}
            </button>
          )}
        </form>
        {step === 'confirm' && (
          <div className="space-y-4">
            <div className="space-y-2">
              <p className="text-xs text-slate-400">A reset token was sent to <span className="text-slate-200">{sentTo}</span>. Enter it below to set a new password.</p>
              {token && (
                <div className="space-y-1">
                  <p className="text-[11px] uppercase tracking-wider text-slate-500">Simulation token (delivered via alert email):</p>
                  <code className="block text-sm bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-emerald-300 break-all">{token}</code>
                </div>
              )}
            </div>
            <form onSubmit={handleConfirmReset} className="space-y-4">
              <div className="space-y-2">
                <label htmlFor="token" className="text-xs uppercase tracking-wide text-slate-400">Reset Token</label>
                <input
                  id="token"
                  name="token"
                  value={tokenInput}
                  onChange={(event) => setTokenInput(event.target.value)}
                  className="w-full bg-[#0d1524] border border-slate-800 focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/30 rounded-xl px-3 py-2 text-sm"
                  placeholder="Paste the token"
                  required
                />
              </div>
              <div className="space-y-2">
                <label htmlFor="new_password" className="text-xs uppercase tracking-wide text-slate-400">New Password</label>
                <input
                  id="new_password"
                  name="new_password"
                  type="password"
                  value={newPassword}
                  onChange={(event) => setNewPassword(event.target.value)}
                  className="w-full bg-[#0d1524] border border-slate-800 focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/30 rounded-xl px-3 py-2 text-sm"
                  placeholder="********"
                  minLength={8}
                  required
                />
              </div>
              {confirmError && (
                <p className="text-xs text-rose-400 bg-rose-500/10 border border-rose-500/30 rounded-lg px-3 py-2">{confirmError}</p>
              )}
              {successMessage && (
                <p className="text-xs text-emerald-300 bg-emerald-500/10 border border-emerald-500/30 rounded-lg px-3 py-2">{successMessage}</p>
              )}
              <button
                type="submit"
                disabled={confirming}
                className="w-full py-3 rounded-xl bg-gradient-to-r from-emerald-500 to-sky-500 hover:from-emerald-400 hover:to-sky-400 text-slate-950 font-semibold shadow-lg shadow-emerald-500/20 transition disabled:opacity-60"
              >
                {confirming ? 'Updating...' : 'Confirm Reset'}
              </button>
            </form>
          </div>
        )}
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
