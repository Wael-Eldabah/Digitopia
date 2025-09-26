// Software-only simulation / demo — no real systems will be contacted or modified.
import React, { useState } from 'react';
import axios from 'axios';
import SimulationTerminal from '../components/SimulationTerminal.jsx';

export default function SimulationPage() {
  const [form, setForm] = useState({ ip_address: '', hostname: '', traffic_gb: 1, device_type: 'Endpoint' });
  const [session, setSession] = useState(null);
  const [error, setError] = useState('');

  const handleChange = (event) => {
    const { name, value } = event.target;
    setForm((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    try {
      const response = await axios.post('/api/v1/simulation/devices', {
        ...form,
        traffic_gb: Number(form.traffic_gb),
      });
      setSession(response.data);
      setError('');
    } catch (err) {
      const message = (err?.response?.data?.detail?.message
        || err?.response?.data?.message
        || 'Failed to add device');
      setError(message);
    }
  };

  return (
    <div className="space-y-6">
      <header>
        <h2 className="text-2xl font-semibold">Simulation Environment</h2>
        <p className="text-sm text-slate-400">Provision virtual devices and trigger automated detections.</p>
      </header>
      <form onSubmit={handleSubmit} className="bg-slate-900 border border-slate-800 rounded-xl p-4 grid grid-cols-1 md:grid-cols-5 gap-4">
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
        <div>
          <label className="block text-xs text-slate-500 mb-1" htmlFor="traffic_gb">Traffic (GB)</label>
          <input
            id="traffic_gb"
            name="traffic_gb"
            type="number"
            min="0"
            step="0.1"
            value={form.traffic_gb}
            onChange={handleChange}
            className="w-full bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-sm"
          />
        </div>
        <div className="flex items-end">
          <button type="submit" className="bg-indigo-500 hover:bg-indigo-600 text-white text-sm px-4 py-2 rounded">
            Add Device
          </button>
        </div>
        {error && <p className="md:col-span-5 text-xs text-rose-400">{error}</p>}
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




