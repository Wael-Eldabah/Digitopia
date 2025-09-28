// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const roles = [
  { label: 'SOC Analyst', value: 'SOC_ANALYST' },
  { label: 'Incident Response', value: 'INCIDENT_RESPONSE' },
  { label: 'Investigator', value: 'INVESTIGATOR' },
];

export default function SignupPage() {
  const navigate = useNavigate();
  const [form, setForm] = useState({
    email: '',
    password: '',
    displayName: '',
    role: 'SOC_ANALYST',
  });
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleChange = (event) => {
    const { name, value } = event.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setSuccess('');
    if (!form.email.endsWith('@eyeguard.com')) {
      setError('Signup is restricted to @eyeguard.com addresses.');
      return;
    }
    setSubmitting(true);
    try {
      await axios.post('/api/v1/auth/signup', {
        email: form.email,
        password: form.password,
        role: form.role,
        display_name: form.displayName,
      });
      setSuccess('Request submitted. A manager will review your signup.');
      setForm({ email: '', password: '', displayName: '', role: 'SOC_ANALYST' });
    } catch (err) {
      const message = err?.response?.data?.detail?.message || 'Unable to submit signup request.';
      setError(message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0b1220] flex items-center justify-center px-4 py-12">
      <div className="w-full max-w-xl bg-[#111a2e] border border-slate-800/80 rounded-3xl shadow-[0_30px_60px_rgba(15,23,42,0.45)] p-10 space-y-8 text-slate-200">
        <div className="space-y-1">
          <h1 className="text-3xl font-semibold tracking-tight">Request Access</h1>
          <p className="text-sm text-slate-400">Submit your details for manager approval.</p>
        </div>
        <form onSubmit={handleSubmit} className="space-y-5">
          <div className="grid sm:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-wide text-slate-400" htmlFor="displayName">Full Name</label>
              <input
                id="displayName"
                name="displayName"
                value={form.displayName}
                onChange={handleChange}
                className="w-full bg-[#0d1524] border border-slate-800 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30 rounded-xl px-3 py-2 text-sm"
                placeholder="Wael Eldabah"
                required
              />
            </div>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-wide text-slate-400" htmlFor="role">Role</label>
              <select
                id="role"
                name="role"
                value={form.role}
                onChange={handleChange}
                className="w-full bg-[#0d1524] border border-slate-800 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30 rounded-xl px-3 py-2 text-sm"
              >
                {roles.map((role) => (
                  <option key={role.value} value={role.value}>{role.label}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="space-y-2">
            <label className="text-xs uppercase tracking-wide text-slate-400" htmlFor="email">Email Address</label>
            <input
              id="email"
              name="email"
              type="email"
              value={form.email}
              onChange={handleChange}
              className="w-full bg-[#0d1524] border border-slate-800 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30 rounded-xl px-3 py-2 text-sm"
              placeholder="you@eyeguard.com"
              required
            />
          </div>
          <div className="space-y-2">
            <label className="text-xs uppercase tracking-wide text-slate-400" htmlFor="password">Temporary Password</label>
            <input
              id="password"
              name="password"
              type="password"
              minLength={8}
              value={form.password}
              onChange={handleChange}
              className="w-full bg-[#0d1524] border border-slate-800 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30 rounded-xl px-3 py-2 text-sm"
              placeholder="At least 8 characters"
              required
            />
            <p className="text-xs text-slate-500">Your password is stored securely.</p>
          </div>
          {error && (
            <p className="text-xs text-rose-400 bg-rose-500/10 border border-rose-500/30 rounded-lg px-3 py-2">{error}</p>
          )}
          {success && (
            <p className="text-xs text-emerald-300 bg-emerald-500/10 border border-emerald-500/30 rounded-lg px-3 py-2">{success}</p>
          )}
          <button
            type="submit"
            disabled={submitting}
            className="w-full py-3 rounded-xl bg-gradient-to-r from-sky-500 to-emerald-500 hover:from-sky-400 hover:to-emerald-400 text-slate-950 font-semibold shadow-lg shadow-emerald-500/20 transition disabled:opacity-60"
          >
            {submitting ? 'Submitting...' : 'Submit Request'}
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