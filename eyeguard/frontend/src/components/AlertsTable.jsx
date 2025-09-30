// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useContext, useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import axios from 'axios';
import AuthContext from '../context/AuthContext.jsx';
import CreateIncidentModal from './CreateIncidentModal.jsx';

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

const formatDateTime = (value) => (value ? new Date(value).toLocaleString() : 'N/A');

const AlertModal = ({ alert, onClose, onRefresh }) => {
  const [pending, setPending] = useState(false);
  const [error, setError] = useState('');

  if (!alert) {
    return null;
  }

  const acknowledge = async () => {
    try {
      setPending(true);
      setError('');
      await axios.post(`/api/v1/alerts/${alert.id}/status`, { status: 'Acknowledged' });
      onRefresh?.();
      onClose();
    } catch (ackErr) {
      setError(
        ackErr?.response?.data?.detail?.message || ackErr?.message || 'Unable to update alert status.',
      );
    } finally {
      setPending(false);
    }
  };

  const guidance = Array.isArray(alert.recommended_actions) ? alert.recommended_actions : [];
  const mitigation = Array.isArray(alert.mitigation_steps) ? alert.mitigation_steps : [];
  const intelSummary = alert.intel_summary || alert.rationale;
  const statusLockedBySystem = Boolean(alert.auto_closed_by_system);
  const isStatusClosed = String(alert.status || '').toLowerCase() === 'closed';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/70 backdrop-blur-sm p-4" role="dialog" aria-modal="true">
      <div className="w-full max-w-[min(480px,90vw)] max-h-[90vh] overflow-y-auto rounded-3xl border border-slate-800/70 bg-[#10192c] p-6 shadow-2xl shadow-slate-900/50 sm:p-8">
        <header className="flex items-start justify-between gap-3">
          <div className="space-y-1">
            <h3 className="text-lg font-semibold text-slate-100">{alert.category}</h3>
            <p className="text-xs uppercase tracking-wide text-slate-500">Alert detail</p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="text-slate-500 transition hover:text-slate-300"
            aria-label="Close alert detail"
          >
            �
          </button>
        </header>

        <dl className="mt-6 grid grid-cols-1 gap-4 text-sm text-slate-200 sm:grid-cols-2">
          <div>
            <dt className="text-xs uppercase tracking-wide text-slate-500">Source IP</dt>
            <dd className="font-mono">{alert.source_ip}</dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-slate-500">Destination IP</dt>
            <dd className="font-mono">{alert.destination_ip || 'N/A'}</dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-slate-500">Severity</dt>
            <dd>
              <span className={`inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold ${
                severityStyles[alert.severity] || severityStyles.Low
              }`}
              >
                {alert.severity}
              </span>
            </dd>
          </div>
          <div>
            <dt className="text-xs uppercase tracking-wide text-slate-500">Detected</dt>
            <dd>{formatDateTime(alert.detected_at)}</dd>
          </div>
        </dl>

        <section className="mt-6 space-y-3 text-sm text-slate-200">
          <div className="rounded-2xl border border-slate-800/60 bg-slate-900/60 p-4">
            <p className="mb-2 text-xs uppercase tracking-wide text-slate-500">Rationale</p>
            <p className="leading-relaxed">{alert.rationale || 'No rationale recorded yet.'}</p>
          </div>
          {intelSummary && intelSummary !== alert.rationale && (
            <div className="rounded-2xl border border-sky-500/30 bg-sky-500/10 p-4">
              <p className="mb-2 text-xs uppercase tracking-wide text-sky-300">Intel summary</p>
              <p className="leading-relaxed">{intelSummary}</p>
            </div>
          )}
          {(guidance.length || mitigation.length) && (
            <div className="grid gap-4 md:grid-cols-2">
              {!!guidance.length && (
                <div>
                  <h4 className="text-xs uppercase tracking-wide text-emerald-300">Recommended actions</h4>
                  <ul className="mt-2 space-y-1 text-xs">
                    {guidance.map((item) => (
                      <li key={item} className="flex items-start gap-2">
                        <span className="mt-1 h-2 w-2 rounded-full bg-emerald-400" aria-hidden="true" />
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {!!mitigation.length && (
                <div>
                  <h4 className="text-xs uppercase tracking-wide text-sky-300">Mitigation steps</h4>
                  <ul className="mt-2 space-y-1 text-xs">
                    {mitigation.map((item) => (
                      <li key={item} className="flex items-start gap-2">
                        <span className="mt-1 h-2 w-2 rounded-full bg-sky-400" aria-hidden="true" />
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </section>

        {error && (
          <p className="mt-4 rounded-xl border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-200">
            {error}
          </p>
        )}

        <footer className="mt-6 flex flex-col gap-2 text-xs text-slate-400 sm:flex-row sm:items-center sm:justify-between">
          <span>Status: <span className={`font-semibold ${statusPalette[alert.status] || 'text-slate-300'}`}>{alert.status}</span></span>
          <div className="flex flex-col gap-2 sm:flex-row sm:gap-3">
            {!statusLockedBySystem && !isStatusClosed && (
              <button
                type="button"
                onClick={acknowledge}
                className="inline-flex items-center justify-center rounded-lg border border-slate-700 px-3 py-2 font-semibold text-slate-200 transition hover:bg-slate-800/60 disabled:cursor-not-allowed disabled:opacity-60"
                disabled={pending}
              >
                {pending ? 'Updating...' : 'Acknowledge'}
              </button>
            )}
            <button
              type="button"
              onClick={onClose}
              className="inline-flex items-center justify-center rounded-lg border border-slate-700 px-3 py-2 font-semibold text-slate-200 transition hover:bg-slate-800/60"
            >
              Close
            </button>
          </div>
        </footer>
      </div>
    </div>
  );
};

const useAlerts = (filters) => {
  return useQuery({
    queryKey: ['alerts', filters],
    enabled: !filters.dateRangeInvalid,
    queryFn: async ({ queryKey }) => {
      const [, params] = queryKey;
      const response = await axios.get('/api/v1/alerts', {
        params: {
          page: params.page,
          page_size: params.pageSize,
          severity: params.severity !== 'All' ? params.severity : undefined,
          status: params.status !== 'All' ? params.status : undefined,
          start_date: params.startDate || undefined,
          end_date: params.endDate || undefined,
        },
      });

      const payload = response.data;
      if (Array.isArray(payload)) {
        const start = (params.page - 1) * params.pageSize;
        const end = start + params.pageSize;
        return {
          items: payload.slice(start, end),
          total: payload.length,
        };
      }
      return {
        items: payload?.items || [],
        total: payload?.total || 0,
      };
    },
    refetchInterval: 30000,
    keepPreviousData: true,
    retry: 1,
  });
};

const AlertCard = ({ alert, onSelect }) => (
  <article className="space-y-2 rounded-2xl border border-slate-800/60 bg-slate-900/40 p-4">
    <div className="flex items-center justify-between">
      <h3 className="text-sm font-semibold text-slate-100">{alert.category}</h3>
      <span className={`inline-flex items-center rounded-full px-3 py-1 text-[11px] font-semibold ${
        severityStyles[alert.severity] || severityStyles.Low
      }`}
      >
        {alert.severity}
      </span>
    </div>
    <dl className="grid grid-cols-2 gap-2 text-xs text-slate-400">
      <div>
        <dt className="uppercase tracking-wide text-slate-500">Detected</dt>
        <dd>{formatDateTime(alert.detected_at)}</dd>
      </div>
      <div className="text-right">
        <dt className="uppercase tracking-wide text-slate-500">Status</dt>
        <dd className={`font-semibold ${statusPalette[alert.status] || 'text-slate-300'}`}>{alert.status}</dd>
      </div>
      <div className="col-span-2">
        <dt className="uppercase tracking-wide text-slate-500">Source IP</dt>
        <dd className="font-mono">{alert.source_ip}</dd>
      </div>
      <div className="col-span-2">
        <dt className="uppercase tracking-wide text-slate-500">Destination IP</dt>
        <dd className="font-mono">{alert.destination_ip || 'N/A'}</dd>
      </div>
    </dl>
    <button
      type="button"
      onClick={() => onSelect(alert)}
      className="inline-flex w-full items-center justify-center rounded-lg border border-slate-700 px-3 py-2 text-xs font-semibold text-sky-300 transition hover:bg-slate-800/60"
    >
      View details
    </button>
  </article>
);

export default function AlertsTable() {
  const { user } = useContext(AuthContext);
  const queryClient = useQueryClient();

  const [severityFilter, setSeverityFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');
  const [startDate, setStartDate] = useState('');
  const [endDate, setEndDate] = useState('');
  const [page, setPage] = useState(1);
  const pageSize = 10;
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [showCreate, setShowCreate] = useState(false);
  const [createError, setCreateError] = useState('');

  const dateRangeInvalid = useMemo(() => {
    if (!startDate || !endDate) return false;
    return new Date(startDate) > new Date(endDate);
  }, [startDate, endDate]);

  const filters = useMemo(
    () => ({
      severity: severityFilter,
      status: statusFilter,
      startDate,
      endDate,
      page,
      pageSize,
      dateRangeInvalid,
    }),
    [severityFilter, statusFilter, startDate, endDate, page, pageSize, dateRangeInvalid],
  );

  const {
    data,
    isLoading,
    isFetching,
    refetch,
    error,
  } = useAlerts(filters);

  const alerts = data?.items || [];
  const total = data?.total || 0;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  useEffect(() => {
    setPage(1);
  }, [severityFilter, statusFilter, startDate, endDate]);

  const createIncident = useMutation({
    mutationFn: (payload) => axios.post('/api/v1/alerts', payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      setShowCreate(false);
    },
    onError: (err) => {
      setCreateError(err?.response?.data?.detail?.message || err?.message || 'Failed to create incident.');
    },
  });

  const handleCreateIncident = (form) => {
    createIncident.mutate({
      source_ip: form.source_ip,
      destination_ip: form.destination_ip || null,
      category: form.category,
      severity: form.severity,
      rationale: form.rationale,
    });
  };

  const fetchError = error?.response?.data?.detail?.message || error?.message || '';

  const canGoPrev = page > 1;
  const canGoNext = page < totalPages;

  useEffect(() => {
    if (page > totalPages) {
      setPage(totalPages);
    }
  }, [page, totalPages]);

  return (
    <section className="rounded-3xl border border-slate-800/70 bg-[#0d172a] shadow-[0_25px_60px_rgba(8,17,32,0.55)]">
      <header className="flex flex-col gap-3 border-b border-slate-800/60 px-4 py-5 sm:flex-row sm:items-center sm:justify-between sm:px-6">
        <div>
          <h2 className="text-xl font-semibold text-slate-100">Alerts &amp; Incidents</h2>
          <p className="text-xs text-slate-500">Monitor high-impact detections and pivot quickly into response.</p>
        </div>
        {user && (
          <button
            type="button"
            className="inline-flex items-center justify-center rounded-xl bg-emerald-500/90 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-emerald-400"
            onClick={() => {
              setCreateError('');
              setShowCreate(true);
            }}
          >
            + Create Incident
          </button>
        )}
      </header>

      <div className="grid grid-cols-1 gap-4 border-b border-slate-800/60 px-4 py-5 sm:grid-cols-2 lg:grid-cols-4 sm:px-6">
        <div className="flex flex-col">
          <label className="mb-2 text-xs uppercase tracking-wide text-slate-500">Severity</label>
          <select
            value={severityFilter}
            onChange={(event) => setSeverityFilter(event.target.value)}
            className="rounded-xl border border-slate-800 bg-slate-900/70 px-3 py-2 text-sm text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30"
          >
            <option>All</option>
             <option>Critical</option>
            <option>High</option>
            <option>Medium</option>
            <option>Low</option>
          </select>
        </div>
        <div className="flex flex-col">
          <label className="mb-2 text-xs uppercase tracking-wide text-slate-500">Status</label>
          <select
            value={statusFilter}
            onChange={(event) => setStatusFilter(event.target.value)}
            className="rounded-xl border border-slate-800 bg-slate-900/70 px-3 py-2 text-sm text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30"
          >
            <option>All</option>
            <option>Open</option>
            <option>Acknowledged</option>
            <option>Resolved</option>
          </select>
        </div>
        <div className="flex flex-col">
          <label className="mb-2 text-xs uppercase tracking-wide text-slate-500">Start Date</label>
          <input
            type="date"
            value={startDate}
            onChange={(event) => setStartDate(event.target.value)}
            className="rounded-xl border border-slate-800 bg-slate-900/70 px-3 py-2 text-sm text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30"
          />
        </div>
        <div className="flex flex-col">
          <label className="mb-2 text-xs uppercase tracking-wide text-slate-500">End Date</label>
          <input
            type="date"
            value={endDate}
            onChange={(event) => setEndDate(event.target.value)}
            className="rounded-xl border border-slate-800 bg-slate-900/70 px-3 py-2 text-sm text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30"
          />
        </div>
      </div>

      {fetchError && (
        <p className="px-4 py-3 text-xs text-rose-200 sm:px-6">
          {fetchError}{' '}
          <button type="button" className="underline" onClick={() => refetch()}>
            Retry
          </button>
        </p>
      )}
      {dateRangeInvalid && (
        <p className="px-4 py-3 text-xs text-amber-300 sm:px-6">
          Invalid date range. Start date must be before end date.
        </p>
      )}

      <div className="space-y-3 border-b border-slate-800/60 px-4 py-4 md:hidden sm:px-6">
        {isLoading && <p className="text-xs text-slate-500">Loading alerts...</p>}
        {!isLoading && alerts.map((alert) => (
          <AlertCard key={alert.id} alert={alert} onSelect={setSelectedAlert} />
        ))}
        {!isLoading && !alerts.length && !fetchError && !dateRangeInvalid && (
          <p className="text-xs text-slate-500">No alerts match the current filters.</p>
        )}
      </div>

      <div className="hidden overflow-x-auto md:block">
        <table className="min-w-full text-sm text-slate-300">
          <thead className="bg-slate-900/60 text-xs uppercase text-slate-500">
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
            {!isLoading && alerts.map((alert) => (
              <tr key={alert.id} className="transition hover:bg-slate-900/40">
                <td className="px-6 py-4 text-xs text-slate-400">{formatDateTime(alert.detected_at)}</td>
                <td className="px-6 py-4 font-medium text-slate-100">{alert.category}</td>
                <td className="px-6 py-4">
                  <span className={`inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold ${
                    severityStyles[alert.severity] || severityStyles.Low
                  }`}
                  >
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
                    onClick={() => setSelectedAlert(alert)}
                    className="text-xs font-semibold text-sky-400 transition hover:text-sky-300"
                  >
                    View
                  </button>
                </td>
              </tr>
            ))}
            {!isLoading && !alerts.length && !fetchError && !dateRangeInvalid && (
              <tr>
                <td colSpan={7} className="px-6 py-12 text-center text-sm text-slate-500">
                  No alerts match the current filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <footer className="flex flex-col gap-3 border-t border-slate-800/60 px-4 py-4 text-center text-xs text-slate-500 sm:flex-row sm:items-center sm:justify-between sm:px-6 sm:text-left">
        <span>
          Showing {alerts.length ? (page - 1) * pageSize + 1 : 0}-
          {Math.min(page * pageSize, total)} of {total} alerts
        </span>
        <div className="flex items-center justify-center gap-3 sm:justify-end">
          <button
            type="button"
            onClick={() => setPage((prev) => Math.max(prev - 1, 1))}
            className="rounded-lg border border-slate-800 px-3 py-1 transition hover:bg-slate-900/60 disabled:cursor-not-allowed disabled:opacity-60"
            disabled={!canGoPrev || isFetching}
          >
            Previous
          </button>
          <span>
            Page {page} of {totalPages}
          </span>
          <button
            type="button"
            onClick={() => setPage((prev) => Math.min(prev + 1, totalPages))}
            className="rounded-lg border border-slate-800 px-3 py-1 transition hover:bg-slate-900/60 disabled:cursor-not-allowed disabled:opacity-60"
            disabled={!canGoNext || isFetching}
          >
            Next
          </button>
        </div>
      </footer>

      <AlertModal
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onRefresh={() => refetch()}
      />
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
    </section>
  );
}
