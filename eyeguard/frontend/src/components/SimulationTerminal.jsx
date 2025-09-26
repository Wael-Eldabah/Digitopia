// Software-only simulation / demo — no real systems will be contacted or modified.
import React, { useState } from 'react';
import axios from 'axios';

export default function SimulationTerminal({ sessionId }) {
  const [command, setCommand] = useState('');
  const [history, setHistory] = useState([]);
  const [alerts, setAlerts] = useState([]);

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!command.trim()) {
      return;
    }
    const response = await axios.post('/api/v1/simulation/terminal', {
      session_id: sessionId,
      command,
    });
    setHistory((prev) => [...prev, `$ ${command}`, response.data.output]);
    if (response.data.alerts_triggered?.length) {
      setAlerts(response.data.alerts_triggered);
    }
    setCommand('');
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl">
      <div className="p-4 border-b border-slate-800">
        <h3 className="text-lg font-semibold">Simulation Terminal</h3>
        <p className="text-xs text-slate-500">Whitelisted commands: ls, cd, nano, edit, mv, rm, ip.</p>
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
          />
          <button type="submit" className="bg-indigo-500 hover:bg-indigo-600 text-sm px-4 py-2 rounded text-white">
            Run
          </button>
        </form>
        {alerts.length > 0 && (
          <div className="border border-amber-500/40 bg-amber-500/10 rounded-md p-3 text-sm">
            <h4 className="font-semibold text-amber-200">Triggered Alerts</h4>
            <ul className="list-disc list-inside text-amber-100 space-y-1">
              {alerts.map((alert) => (
                <li key={alert.id}>
                  <span className="font-semibold">{alert.category}</span> — {alert.rationale}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
}
