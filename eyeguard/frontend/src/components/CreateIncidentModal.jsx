// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useState } from 'react';

const severities = ['Critical', 'High', 'Medium', 'Low'];

export default function CreateIncidentModal({ onCreate, onClose, isSubmitting, errorMessage }) {
  const [form, setForm] = useState({
    source_ip: '',
    destination_ip: '',
    category: 'Manual Incident',
    severity: 'Medium',
    rationale: '',
  });
  const [localError, setLocalError] = useState('');

  const handleChange = (event) => {
    const { name, value } = event.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = (event) => {
    event.preventDefault();
    if (!form.source_ip || !form.category) {
      setLocalError('Source IP and category are required.');
      return;
    }
    setLocalError('');
    onCreate(form);
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/70 backdrop-blur flex items-center justify-center p-4">
      <div className="w-full max-w-2xl bg-[#10192c] border border-slate-800/70 rounded-3xl shadow-2xl shadow-slate-900/40 p-8 space-y-6">
        <div className="flex items-start justify-between">
          <div>
            <h3 className="text-xl font-semibold text-slate-100">Create Incident</h3>
            <p className="text-xs uppercase text-slate-500 tracking-wide">Register a manual alert</p>
          </div>
          <button type="button" onClick={onClose} className="text-slate-500 hover:text-slate-300 transition" aria-label="Close incident modal">
            <span aria-hidden="true">X</span>
          </button>
        </div>
        <form onSubmit={handleSubmit} className="space-y-5">
          <div className="grid md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-wide text-slate-500" htmlFor="source_ip">Source IP</label>
              <input
                id="source_ip"
                name="source_ip"
                value={form.source_ip}
                onChange={handleChange}
                className="w-full bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30"
                placeholder="198.51.100.42"
                required
              />
            </div>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-wide text-slate-500" htmlFor="destination_ip">Destination IP</label>
              <input
                id="destination_ip"
                name="destination_ip"
                value={form.destination_ip}
                onChange={handleChange}
                className="w-full bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30"
                placeholder="203.0.113.9"
              />
            </div>
          </div>
          <div className="grid md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-wide text-slate-500" htmlFor="category">Category</label>
              <input
                id="category"
                name="category"
                value={form.category}
                onChange={handleChange}
                className="w-full bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30"
                placeholder="Suspicious Login"
                required
              />
            </div>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-wide text-slate-500" htmlFor="severity">Severity</label>
              <select
                id="severity"
                name="severity"
                value={form.severity}
                onChange={handleChange}
                className="w-full bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30"
              >
                {severities.map((option) => (
                  <option key={option} value={option}>{option}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="space-y-2">
            <label className="text-xs uppercase tracking-wide text-slate-500" htmlFor="rationale">Rationale</label>
            <textarea
              id="rationale"
              name="rationale"
              value={form.rationale}
              onChange={handleChange}
              className="w-full bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30"
              placeholder="Describe why this alert is being raised."
              rows={4}
            />
          </div>
          {(localError || errorMessage) && (
            <p className="text-xs text-rose-400 bg-rose-500/10 border border-rose-500/30 rounded-lg px-3 py-2">{localError || errorMessage}</p>
          )}
          <div className="flex justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-xl border border-slate-700 text-xs font-semibold text-slate-300 hover:bg-slate-900/50 transition"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-4 py-2 rounded-xl bg-emerald-500/80 text-slate-950 text-xs font-semibold hover:bg-emerald-400 transition disabled:opacity-60"
            >
              {isSubmitting ? 'Creating...' : 'Create Incident'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}