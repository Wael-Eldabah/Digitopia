// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useContext, useState } from 'react';
import axios from 'axios';
import SimulationTerminal from '../components/SimulationTerminal.jsx';
import { SimulationContext } from '../context/SimulationContext.jsx';

export default function SimulationPage() {
  const { session, startSession, endSession, statusMessage, setStatusMessage } = useContext(SimulationContext);
  const [form, setForm] = useState(() => ({ ip_address: '', hostname: '', device_type: 'Endpoint' }));
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleChange = (event) => {
    const { name, value } = event.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setSubmitting(true);
    setError('');
    try {
      try {
        const { data: blockStatus } = await axios.get('/api/blocklist/check', { params: { ip: form.ip_address } });
        if (blockStatus?.blocked) {
          setStatusMessage('IP is currently on the blocklist. Simulation will be blocked.');
        } else {
          setStatusMessage(null);
        }
      } catch (checkErr) {
        setStatusMessage(null);
      }
      const response = await axios.post('/api/v1/simulation/devices', {
        ...form,
      });
      startSession(response.data);
    } catch (err) {
      const message = err?.response?.data?.detail?.message
        || err?.response?.data?.message
        || 'Failed to add device';
      setError(message);
    } finally {
      setSubmitting(false);
    }
  };

  const handleEndSession = async () => {
    setError('');
    await endSession();
  };

  const blocked = Boolean(session?.blocked);

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 className="text-2xl font-semibold">Simulation Environment</h2>
          <p className="text-sm text-slate-400">Provision virtual devices and trigger automated detections.</p>
        </div>
        {session && (
          <button
            type="button"
            onClick={handleEndSession}
            className="inline-flex items-center justify-center rounded-lg border border-slate-700 bg-slate-900 px-4 py-2 text-sm font-semibold text-slate-200 hover:border-rose-400 hover:text-rose-200 transition"
          >
            End Session
          </button>
        )}
      </header>

      {statusMessage && (
        <div
          className={`${blocked ? 'border-rose-500/50 bg-rose-500/10 text-rose-200' : 'border-sky-500/40 bg-sky-500/10 text-sky-100'} border rounded-xl px-4 py-3 text-sm`}
        >
          {statusMessage}
        </div>
      )}

      <form onSubmit={handleSubmit} className="bg-slate-900 border border-slate-800 rounded-xl p-4 grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="md:col-span-2">
          <label className="block text-xs text-slate-500 mb-1" htmlFor="ip_address">IP Address</label>
          <input
            id="ip_address"
            name="ip_address"
            value={form.ip_address}
            onChange={handleChange}
            className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-sm"
            placeholder="192.0.2.42"
            required
          />
        </div>
        <div className="md:col-span-1">
          <label className="block text-xs text-slate-500 mb-1" htmlFor="hostname">Hostname</label>
          <input
            id="hostname"
            name="hostname"
            value={form.hostname}
            onChange={handleChange}
            className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-sm"
            placeholder="training-node"
            required
          />
        </div>
        <div>
          <label className="block text-xs text-slate-500 mb-1" htmlFor="device_type">Device Type</label>
          <input
            id="device_type"
            name="device_type"
            value={form.device_type}
            onChange={handleChange}
            className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-sm"
          />
        </div>
        <div className="flex items-end">
          <button
            type="submit"
            className="bg-indigo-500 hover:bg-indigo-600 text-white text-sm px-4 py-2 rounded disabled:opacity-60"
            disabled={submitting}
          >
            {submitting ? 'Creating...' : 'Add Device'}
          </button>
        </div>
        {error && <p className="md:col-span-4 text-xs text-rose-400">{error}</p>}
      </form>

      {session ? (
        <SimulationTerminal sessionId={session.session_id} />
      ) : (
        <div className="border border-slate-800 rounded-xl p-6 text-sm text-slate-500 bg-slate-900">
          Provision a device to start a simulation session. Alerts will stream when rules trigger (restricted folders, file changes, high traffic).
        </div>
      )}
    </div>
  );
}
