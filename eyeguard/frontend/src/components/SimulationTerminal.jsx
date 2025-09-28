// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useContext, useState } from 'react';
import axios from 'axios';
import { SimulationContext } from '../context/SimulationContext.jsx';

export default function SimulationTerminal({ sessionId }) {
  const {
    session,
    history,
    alerts,
    appendHistory,
    setAlerts,
  } = useContext(SimulationContext);
  const [command, setCommand] = useState('');
  const [pending, setPending] = useState(false);
  const blocked = session?.blocked;

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!command.trim()) {
      return;
    }
    if (blocked) {
      appendHistory(`$ ${command}`);
      appendHistory('Session is blocked. End the simulation to start a new session.');
      setCommand('');
      return;
    }
    setPending(true);
    try {
      const response = await axios.post('/api/v1/simulation/terminal', {
        session_id: sessionId,
        command,
      });
      appendHistory([`$ ${command}`, response.data.output]);
      if (Array.isArray(response.data.alerts_triggered) && response.data.alerts_triggered.length > 0) {
        setAlerts(response.data.alerts_triggered);
      } else {
        setAlerts([]);
      }
    } catch (err) {
      const message = err?.response?.data?.detail?.message
        || err?.response?.data?.error
        || 'Command execution failed.';
      appendHistory([`$ ${command}`, message]);
    } finally {
      setCommand('');
      setPending(false);
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl">
      <div className="p-4 border-b border-slate-800">
        <h3 className="text-lg font-semibold">Simulation Terminal</h3>
        <p className="text-xs text-slate-500">Whitelisted commands: ls, cd, nano, edit, mv, rm, ip.</p>
        {blocked && (
          <p className="mt-2 text-xs text-rose-300">Session is blocked. End the current session to start a new simulation.</p>
        )}
      </div>
      <div className="p-4 space-y-3">
        <div className="bg-slate-950 border border-slate-800 rounded-md p-3 h-48 overflow-y-auto text-sm font-mono">
          {history.length === 0 && <div className="text-slate-600">Start typing commands to interact with the device...</div>}
          {history.map((entry, index) => (
            <div key={index} className="whitespace-pre-wrap">
              {entry}
            </div>
          ))}
        </div>
        <form onSubmit={handleSubmit} className="flex gap-2">
          <span className="text-slate-600 font-mono pt-2">$</span>
          <input
            className="flex-1 bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500"
            value={command}
            onChange={(event) => setCommand(event.target.value)}
            placeholder="Enter command"
            disabled={pending || blocked}
          />
          <button
            type="submit"
            className="bg-indigo-500 hover:bg-indigo-600 text-sm px-4 py-2 rounded text-white disabled:opacity-60"
            disabled={pending || blocked}
          >
            {pending ? 'Running...' : 'Run'}
          </button>
        </form>
        {alerts.length > 0 && (
          <div className="border border-amber-500/40 bg-amber-500/10 rounded-md p-3 text-sm">
            <h4 className="font-semibold text-amber-200">Triggered Alerts</h4>
            <ul className="list-disc list-inside text-amber-100 space-y-1">
              {alerts.map((alert) => (
                <li key={alert.id}>
                  <span className="font-semibold">{alert.category}</span> - {alert.rationale}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}
