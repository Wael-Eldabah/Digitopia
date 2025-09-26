// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useContext, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import axios from 'axios';
import { AuthContext } from '../App.jsx';
import CreateIncidentModal from './CreateIncidentModal.jsx';

const fetchAlerts = async () => {
  const response = await axios.get('/api/v1/alerts');
  return response.data;
};

const severityStyles = {
  High: 'bg-rose-500/15 text-rose-300 border border-rose-400/30',
  Medium: 'bg-amber-500/15 text-amber-300 border border-amber-400/30',
  Low: 'bg-emerald-500/15 text-emerald-300 border border-emerald-400/20',
};

const statusPalette = {
  Open: 'text-amber-300',
  Resolved: 'text-emerald-300',
  Acknowledged: 'text-sky-300',
};

function AlertModal({ alert, onClose, onUpdate }) {
  if (!alert) {
    return null;
  }

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/70 backdrop-blur flex items-center justify-center p-4">
      <div className="w-full max-w-xl bg-[#10192c] border border-slate-800/70 rounded-3xl shadow-2xl shadow-slate-900/40 p-8 space-y-6">
        <div className="flex items-start justify-between">
          <div>
            <h3 className="text-xl font-semibold text-slate-100">{alert.category}</h3>
            <p className="text-xs uppercase text-slate-500 tracking-wide">Alert Detail</p>
          </div>
          <button type="button" onClick={() => onClose()} className="text-slate-500 hover:text-slate-300 transition" aria-label="Close alert detail">
            <span aria-hidden="true">X</span>
          </button>
        </div>
        <div className="grid grid-cols-2 gap-5 text-sm">
          <div className="space-y-1">
            <p className="text-xs text-slate-500">Source IP</p>
            <p className="font-medium text-slate-200">{alert.source_ip}</p>
          </div>
          <div className="space-y-1">
            <p className="text-xs text-slate-500">Destination IP</p>
            <p className="font-medium text-slate-200">{alert.destination_ip || 'N/A'}</p>
          </div>
          <div className="space-y-1">
            <p className="text-xs text-slate-500">Severity</p>
            <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold ${severityStyles[alert.severity] || severityStyles.Low}`}>
              {alert.severity}
            </span>
          </div>
          <div className="space-y-1">
            <p className="text-xs text-slate-500">Detected</p>
            <p className="font-medium text-slate-200">{new Date(alert.detected_at).toLocaleString()}</p>
          </div>
        </div>
        <div>
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Rationale</p>
          <p className="text-sm text-slate-200 leading-relaxed bg-slate-900/60 border border-slate-800/60 rounded-2xl p-4">
            {alert.rationale || 'No rationale recorded yet.'}
          </p>
        </div>
        <div className="flex justify-end gap-3">
          <button
            type="button"
            onClick={() => onUpdate('Resolved')}
            className="px-4 py-2 rounded-xl border border-emerald-400/40 text-xs font-semibold text-emerald-200 hover:bg-emerald-500/10 transition"
          >
            Mark Resolved
          </button>
          <button
            type="button"
            onClick={() => onUpdate('Acknowledged')}
            className="px-4 py-2 rounded-xl bg-sky-500/80 text-slate-900 font-semibold text-xs hover:bg-sky-400 transition"
          >
            Acknowledge
          </button>
        </div>
      </div>
    </div>
  );
}

export default function AlertsTable() {
  const queryClient = useQueryClient();
  const { user } = useContext(AuthContext);
  const { data: alerts = [], isLoading } = useQuery({
    queryKey: ['alerts'],
    queryFn: fetchAlerts,
    refetchInterval: 5000,
  });
  const [severityFilter, setSeverityFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');
  const [selected, setSelected] = useState(null);
  const [showCreate, setShowCreate] = useState(false);
  const [createError, setCreateError] = useState('');

  const updateStatus = useMutation({
    mutationFn: ({ id, status }) => axios.post(`/api/v1/alerts/${id}/status`, { status }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['alerts'] }),
  });

  const createIncident = useMutation({
    mutationFn: (payload) => axios.post('/api/v1/alerts', payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      setShowCreate(false);
      setCreateError('');
    },
    onError: (mutationError) => {
      const message = mutationError?.response?.data?.detail?.message || 'Failed to create incident.';
      setCreateError(message);
    },
  });

  const filteredAlerts = useMemo(() => {
    return alerts.filter((alert) => {
      const severityMatch = severityFilter === 'All' || alert.severity === severityFilter;
      const statusMatch = statusFilter === 'All' || alert.status === statusFilter;
      return severityMatch && statusMatch;
    });
  }, [alerts, severityFilter, statusFilter]);

  const handleUpdate = (status) => {
    if (selected && status) {
      updateStatus.mutate({ id: selected.id, status });
    }
    setSelected(null);
  };

  const handleCreateIncident = (form) => {
    createIncident.mutate({
      source_ip: form.source_ip,
      destination_ip: form.destination_ip || null,
      category: form.category,
      severity: form.severity,
      rationale: form.rationale,
    });
  };

  return (
    <div className="bg-[#0d172a] border border-slate-800/70 rounded-3xl shadow-[0_18px_50px_rgba(7,16,31,0.55)] relative">
      <div className="flex items-center justify-between px-6 py-5 border-b border-slate-800/60">
        <div>
          <h2 className="text-xl font-semibold text-slate-100">Alerts & Incidents</h2>
          <p className="text-xs text-slate-500">Monitor high-impact detections and pivot quickly into response.</p>
        </div>
        {user && (
          <button
            type="button"
            className="px-4 py-2 rounded-xl bg-emerald-500/90 text-slate-950 font-semibold text-sm hover:bg-emerald-400 transition"
            onClick={() => {
              setCreateError('');
              setShowCreate(true);
            }}
          >
            + Create Incident
          </button>
        )}
      </div>
      <div className="px-6 py-5 grid grid-cols-1 lg:grid-cols-[repeat(4,minmax(0,1fr))] gap-4 border-b border-slate-800/60">
        <div className="flex flex-col">
          <label className="text-xs text-slate-500 mb-2 uppercase tracking-wide">Severity</label>
          <select
            value={severityFilter}
            onChange={(event) => setSeverityFilter(event.target.value)}
            className="bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30"
          >
            <option>All</option>
            <option>High</option>
            <option>Medium</option>
            <option>Low</option>
          </select>
        </div>
        <div className="flex flex-col">
          <label className="text-xs text-slate-500 mb-2 uppercase tracking-wide">Status</label>
          <select
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
            className="bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30"
          >
            <option>All</option>
            <option>Open</option>
            <option>Acknowledged</option>
            <option>Resolved</option>
          </select>
        </div>
        <div className="flex flex-col">
          <label className="text-xs text-slate-500 mb-2 uppercase tracking-wide">Start Date</label>
          <input type="date" className="bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30" />
        </div>
        <div className="flex flex-col">
          <label className="text-xs text-slate-500 mb-2 uppercase tracking-wide">End Date</label>
          <input type="date" className="bg-slate-900/70 border border-slate-800 rounded-xl px-3 py-2 text-sm text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30" />
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full text-sm text-slate-300">
          <thead className="text-xs uppercase text-slate-500 bg-slate-900/60">
            <tr>
              <th className="px-6 py-3">Date</th>
              <th className="px-6 py-3">Alert Type</th>
              <th className="px-6 py-3">Severity</th>
              <th className="px-6 py-3">Source IP</th>
              <th className="px-6 py-3">Destination</th>
              <th className="px-6 py-3">Status</th>
              <th className="px-6 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {isLoading && (
              <tr>
                <td colSpan={7} className="px-6 py-16 text-center text-slate-500">
                  Loading alerts...
                </td>
              </tr>
            )}
            {!isLoading && filteredAlerts.map((alert) => (
              <tr key={alert.id} className="hover:bg-slate-900/40 transition">
                <td className="px-6 py-4 text-slate-400 text-xs">{new Date(alert.detected_at).toLocaleString()}</td>
                <td className="px-6 py-4 font-medium text-slate-100">{alert.category}</td>
                <td className="px-6 py-4">
                  <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold ${severityStyles[alert.severity] || severityStyles.Low}`}>
                    {alert.severity}
                  </span>
                </td>
                <td className="px-6 py-4">
                  <span className="font-mono text-xs text-slate-300">{alert.source_ip}</span>
                </td>
                <td className="px-6 py-4">
                  <span className="font-mono text-xs text-slate-300">{alert.destination_ip || 'N/A'}</span>
                </td>
                <td className="px-6 py-4">
                  <span className={`text-xs font-semibold ${statusPalette[alert.status] || 'text-slate-300'}`}>{alert.status}</span>
                </td>
                <td className="px-6 py-4 text-right">
                  <button
                    type="button"
                    onClick={() => setSelected(alert)}
                    className="text-sky-400 hover:text-sky-300 text-xs font-semibold"
                  >
                    View
                  </button>
                </td>
              </tr>
            ))}
            {!isLoading && filteredAlerts.length === 0 && (
              <tr>
                <td colSpan={7} className="px-6 py-12 text-center text-slate-500 text-sm">
                  No alerts match the current filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="flex items-center justify-between px-6 py-4 text-xs text-slate-500 border-t border-slate-800/60">
        <span>Showing {filteredAlerts.length} of {alerts.length} alerts</span>
        <div className="flex items-center gap-3">
          <button type="button" className="px-3 py-1 rounded-lg border border-slate-800 hover:bg-slate-900/60 transition">Previous</button>
          <button type="button" className="px-3 py-1 rounded-lg border border-slate-800 hover:bg-slate-900/60 transition">Next</button>
        </div>
      </div>
      <AlertModal alert={selected} onClose={() => setSelected(null)} onUpdate={handleUpdate} />
      {showCreate && (
        <CreateIncidentModal
          onCreate={handleCreateIncident}
          onClose={() => {
            setCreateError('');
            setShowCreate(false);
          }}
          isSubmitting={createIncident.isPending}
          errorMessage={createError}
        />
      )}
    </div>
  );
}