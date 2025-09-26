// Software-only simulation / demo - no real systems will be contacted or modified.
import React from 'react';
import SettingsPanel from '../components/SettingsPanel.jsx';

export default function SettingsPage() {
  return (
    <div className="space-y-8">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold text-slate-100">Settings</h1>
        <p className="text-sm text-slate-400">Control user access, notifications, and integration keys for the sandbox.</p>
      </header>
      <SettingsPanel />
    </div>
  );
}
