// Software-only simulation / demo - no real systems will be contacted or modified.
import React from 'react';
import AlertsTable from '../components/AlertsTable.jsx';

export default function AlertsPage() {
  return (
    <div className="space-y-6">
      <header className="space-y-1">
        <h1 className="text-3xl font-semibold text-slate-100">Alerts & Incidents</h1>
        <p className="text-sm text-slate-400">Triaging queue for simulated detections and orchestrated response.</p>
      </header>
      <AlertsTable />
    </div>
  );
}
