// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useMemo, useState } from 'react';
import axios from 'axios';
import { useQuery } from '@tanstack/react-query';

const statusBadges = {
  Active: 'border border-rose-400/40 bg-rose-500/10 text-rose-100',
  Monitoring: 'border border-sky-400/40 bg-sky-500/10 text-sky-100',
  Contained: 'border border-emerald-400/40 bg-emerald-500/10 text-emerald-100',
  Closed: 'border border-slate-600/40 bg-slate-700/30 text-slate-200',
};

const severityBadges = {
  Critical: 'border border-rose-500/40 bg-rose-600/20 text-rose-100',
  High: 'border border-orange-400/40 bg-orange-500/20 text-orange-100',
  Medium: 'border border-amber-300/40 bg-amber-400/20 text-amber-100',
  Low: 'border border-emerald-400/40 bg-emerald-500/20 text-emerald-100',
  Info: 'border border-sky-400/40 bg-sky-500/20 text-sky-100',
};

const fetchIncidents = async () => {
  const { data } = await axios.get('/api/v1/incidents');
  if (Array.isArray(data)) {
    return data;
  }
  return data?.items || [];
};

const fetchIncidentDetail = async ({ queryKey }) => {
  const [, incidentId] = queryKey;
  if (!incidentId) {
    return null;
  }
  const { data } = await axios.get(`/api/v1/incidents/${incidentId}`);
  return data;
};

const formatDateTime = (value) => (value ? new Date(value).toLocaleString() : 'N/A');

const relativeTime = (value) => {
  if (!value) {
    return '';
  }
  const now = Date.now();
  const dateValue = new Date(value).getTime();
  const diffMs = Math.max(0, now - dateValue);
  const diffMinutes = Math.round(diffMs / 60000);
  if (diffMinutes < 1) {
    return 'just now';
  }
  if (diffMinutes < 60) {
    return `${diffMinutes} minute${diffMinutes === 1 ? '' : 's'} ago`;
  }
  const diffHours = Math.round(diffMinutes / 60);
  if (diffHours < 24) {
    return `${diffHours} hour${diffHours === 1 ? '' : 's'} ago`;
  }
  const diffDays = Math.round(diffHours / 24);
  return `${diffDays} day${diffDays === 1 ? '' : 's'} ago`;
};

function IncidentDetailModal({ incidentId, onClose }) {
  const { data, isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ['incident-detail', incidentId],
    queryFn: fetchIncidentDetail,
    enabled: Boolean(incidentId),
    staleTime: 30000,
  });

  if (!incidentId) {
    return null;
  }

  const incident = data;
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 backdrop-blur-sm p-4" role="dialog" aria-modal="true">
      <div className="w-full max-w-3xl max-h-[90vh] overflow-y-auto rounded-3xl border border-slate-800/70 bg-[#10192c] p-6 shadow-2xl shadow-slate-900/50 sm:p-8">
        <header className="flex items-start justify-between gap-4">
          <div>
            <h3 className="text-xl font-semibold text-slate-100">Campaign detail</h3>
            <p className="text-xs uppercase tracking-wide text-slate-500">Correlated alerts</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-500 transition hover:text-slate-300"
            aria-label="Close incident detail"
          >
            ✕
          </button>
        </header>

        {isLoading ? (
          <div className="mt-6 text-sm text-slate-400">Loading campaign detail...</div>
        ) : isError ? (
          <div className="mt-6 space-y-3">
            <p className="text-sm text-rose-300">{error?.response?.data?.detail?.message || error?.message || 'Failed to load incident detail.'}</p>
            <button
              type="button"
              onClick={() => refetch()}
              className="inline-flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 text-xs font-semibold text-slate-200 hover:bg-slate-800/60"
            >
              Retry
            </button>
          </div>
        ) : (
          incident && (
            <div className="mt-6 space-y-6">
              <div className="flex flex-col gap-4 rounded-2xl border border-slate-800/60 bg-slate-900/60 p-5 sm:flex-row sm:items-center sm:justify-between">
                <div className="space-y-2">
                  <p className="text-xs uppercase tracking-wide text-slate-500">Campaign</p>
                  <h4 className="text-lg font-semibold text-slate-100">{incident.name}</h4>
                  <p className="text-sm text-slate-300">{incident.summary}</p>
                  <div className="flex flex-wrap gap-3 text-[11px] text-slate-400">
                    <span>First seen {formatDateTime(incident.first_seen)}</span>
                    <span>Last seen {formatDateTime(incident.last_seen)}</span>
                    <span>{incident.alert_count} alert{incident.alert_count === 1 ? '' : 's'}</span>
                  </div>
                </div>
                <div className="flex flex-col items-start gap-2 sm:items-end">
                  <span className={`inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold ${statusBadges[incident.status] || statusBadges.Active}`}>
                    {incident.status}
                  </span>
                  <span className={`inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold ${severityBadges[incident.severity] || severityBadges.Low}`}>
                    Peak {incident.severity}
                  </span>
                  {isFetching && <span className="text-[11px] text-slate-500">Syncing...</span>}
                </div>
              </div>

              <section className="space-y-3">
                <h5 className="text-sm font-semibold text-slate-200">Correlated alerts</h5>
                {incident.alerts?.length ? (
                  <ul className="space-y-2">
                    {incident.alerts.map((item) => (
                      <li key={item.id} className="rounded-2xl border border-slate-800/60 bg-slate-900/50 p-4">
                        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                          <div>
                            <p className="text-sm font-semibold text-slate-100">{item.category}</p>
                            <p className="text-[11px] uppercase tracking-wide text-slate-500">{formatDateTime(item.detected_at)}</p>
                          </div>
                          <div className="flex flex-wrap gap-2">
                            <span className={`inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold ${severityBadges[item.severity] || severityBadges.Low}`}>
                              {item.severity}
                            </span>
                            <span className="inline-flex items-center rounded-full border border-slate-700 px-3 py-1 text-[11px] font-semibold text-slate-300">
                              {item.status}
                            </span>
                          </div>
                        </div>
                        <div className="mt-3 grid gap-3 text-xs text-slate-400 sm:grid-cols-2">
                          <div>
                            <p className="uppercase tracking-wide text-slate-500">Source</p>
                            <p className="font-mono text-slate-200">{item.source_ip}</p>
                          </div>
                          <div>
                            <p className="uppercase tracking-wide text-slate-500">Destination</p>
                            <p className="font-mono text-slate-200">{item.destination_ip || 'N/A'}</p>
                          </div>
                        </div>
                        {item.rationale && (
                          <p className="mt-3 text-xs text-slate-300">{item.rationale}</p>
                        )}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-slate-400">No alerts linked to this campaign yet.</p>
                )}
              </section>

              <section className="space-y-3">
                <h5 className="text-sm font-semibold text-slate-200">Correlation timeline</h5>
                {incident.timeline?.length ? (
                  <ol className="space-y-2 text-xs text-slate-400">
                    {incident.timeline.map((entry) => (
                      <li key={`${entry.timestamp}-${entry.event}`} className="rounded-xl border border-slate-800/60 bg-slate-900/40 px-3 py-2">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <span className="font-semibold text-slate-200">{entry.event}</span>
                          <span className="text-[11px] text-slate-500">{formatDateTime(entry.timestamp)} ({relativeTime(entry.timestamp)})</span>
                        </div>
                        {entry.metadata && Object.keys(entry.metadata).length > 0 && (
                          <div className="mt-2 grid gap-2 text-[11px] sm:grid-cols-2">
                            {Object.entries(entry.metadata).map(([key, value]) => (
                              <span key={key} className="text-slate-400">
                                {key}: <span className="text-slate-200">{String(value)}</span>
                              </span>
                            ))}
                          </div>
                        )}
                        <p className="mt-1 text-[11px] text-slate-500">Actor: {entry.actor}</p>
                      </li>
                    ))}
                  </ol>
                ) : (
                  <p className="text-sm text-slate-400">No activity logged for this campaign yet.</p>
                )}
              </section>
            </div>
          )
        )}
      </div>
    </div>
  );
}

export default function IncidentCampaigns() {
  const [activeIncidentId, setActiveIncidentId] = useState('');
  const { data: incidents = [], isLoading, isError, error, refetch, isFetching } = useQuery({
    queryKey: ['incidents'],
    queryFn: fetchIncidents,
    refetchInterval: 60000,
    staleTime: 30000,
  });

  const visibleIncidents = useMemo(() => incidents.slice(0, 6), [incidents]);
  const hasContent = visibleIncidents.length > 0;

  if (!isLoading && !hasContent && !isError) {
    return null;
  }

  return (
    <section className="space-y-4">
      <header className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-xl font-semibold text-slate-100">Correlated campaigns</h2>
          <p className="text-sm text-slate-400">Alerts grouped by proximity in time and behavior to reduce noise.</p>
        </div>
        <div className="flex items-center gap-3 text-xs text-slate-500">
          {isFetching && <span>Syncing...</span>}
          <button
            type="button"
            onClick={() => refetch()}
            className="inline-flex items-center gap-1 rounded-lg border border-slate-700 px-3 py-1.5 font-semibold text-slate-300 transition hover:bg-slate-800/60"
          >
            Refresh
          </button>
        </div>
      </header>

      {isLoading ? (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {[...Array(3)].map((_, index) => (
            <div key={index} className="h-32 animate-pulse rounded-2xl border border-slate-800/60 bg-slate-900/40" />
          ))}
        </div>
      ) : isError ? (
        <div className="rounded-2xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">
          {error?.response?.data?.detail?.message || error?.message || 'Unable to load correlated campaigns.'}
        </div>
      ) : (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {visibleIncidents.map((incident) => (
            <article key={incident.id} className="flex h-full flex-col justify-between rounded-2xl border border-slate-800/60 bg-slate-900/40 p-4 shadow-[0_18px_45px_rgba(8,18,35,0.35)]">
              <div className="space-y-3">
                <div className="flex items-center justify-between gap-2">
                  <span className={`inline-flex items-center rounded-full px-3 py-1 text-[11px] font-semibold ${statusBadges[incident.status] || statusBadges.Active}`}>
                    {incident.status}
                  </span>
                  <span className={`inline-flex items-center rounded-full px-3 py-1 text-[11px] font-semibold ${severityBadges[incident.severity] || severityBadges.Low}`}>
                    Peak {incident.severity}
                  </span>
                </div>
                <h3 className="text-sm font-semibold text-slate-100">{incident.name}</h3>
                <p className="text-xs text-slate-400 leading-relaxed">{incident.summary}</p>
              </div>
              <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-[11px] text-slate-400">
                <span>{incident.alert_count} alert{incident.alert_count === 1 ? '' : 's'}</span>
                <span>Last activity {relativeTime(incident.last_seen)}</span>
              </div>
              <button
                type="button"
                onClick={() => setActiveIncidentId(incident.id)}
                className="mt-4 inline-flex items-center justify-center rounded-lg border border-slate-700 px-3 py-2 text-xs font-semibold text-sky-300 transition hover:bg-slate-800/60"
              >
                View details
              </button>
            </article>
          ))}
        </div>
      )}

      {activeIncidentId && (
        <IncidentDetailModal
          incidentId={activeIncidentId}
          onClose={() => setActiveIncidentId('')}
        />
      )}
    </section>
  );
}
