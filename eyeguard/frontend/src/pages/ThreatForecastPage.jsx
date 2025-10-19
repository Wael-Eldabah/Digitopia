// Software-only simulation / demo - no real systems will be contacted or modified.
import React from 'react';
import axios from 'axios';
import { useQuery } from '@tanstack/react-query';

const confidenceStyles = {
  High: 'border border-emerald-400/40 bg-emerald-500/10 text-emerald-100',
  Medium: 'border border-amber-300/40 bg-amber-400/10 text-amber-100',
  Low: 'border border-slate-600/40 bg-slate-700/30 text-slate-200',
};

const trendStyles = {
  Increasing: 'text-emerald-300',
  Stable: 'text-sky-300',
  Decreasing: 'text-amber-300',
};

const fetchForecast = async () => {
  const { data } = await axios.get('/api/v1/predictions/forecast', { params: { horizon_hours: 24 } });
  return data;
};

const trendLabel = (direction) => {
  if (direction === 'Increasing') return 'Rising risk trajectory';
  if (direction === 'Decreasing') return 'Risk cooling trend';
  return 'Stable risk outlook';
};

const formatDateTime = (value) => (value ? new Date(value).toLocaleString() : 'N/A');

const RiskBar = ({ score }) => {
  const clamped = Math.min(100, Math.max(0, score));
  return (
    <div className="relative h-2 rounded-full bg-slate-800/60">
      <div className="absolute inset-y-0 left-0 rounded-full bg-gradient-to-r from-sky-500 via-indigo-500 to-emerald-400" style={{ width: `${clamped}%` }} />
    </div>
  );
};

const EmptyState = () => (
  <div className="rounded-3xl border border-slate-800/60 bg-slate-900/40 p-8 text-center text-sm text-slate-400">
    <p>No forecast insights available yet. Generate alerts or simulations to feed the predictive models.</p>
  </div>
);

const EntityList = ({ title, subtitle, items }) => (
  <section className="space-y-4">
    <header className="space-y-1">
      <h3 className="text-lg font-semibold text-slate-100">{title}</h3>
      <p className="text-xs text-slate-500">{subtitle}</p>
    </header>
    {items.length === 0 ? (
      <div className="rounded-2xl border border-slate-800/60 bg-slate-900/40 px-4 py-6 text-sm text-slate-400">
        No elevated entities detected in this horizon.
      </div>
    ) : (
      <ul className="space-y-3">
        {items.map((item) => (
          <li key={`${item.entity}-${item.predicted_vector}`} className="rounded-2xl border border-slate-800/60 bg-slate-900/50 p-4 shadow-[0_18px_45px_rgba(8,18,35,0.35)]">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <p className="text-sm font-semibold text-slate-100">{item.entity}</p>
                <p className="text-xs uppercase tracking-wide text-slate-500">{item.entity_type}</p>
              </div>
              <div className="flex flex-wrap items-center gap-3">
                <span className={`inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold ${confidenceStyles[item.confidence] || confidenceStyles.Low}`}>
                  {item.confidence} confidence
                </span>
                <span className="text-xs font-semibold text-slate-300">Risk score {item.risk_score}</span>
              </div>
            </div>
            <div className="mt-3 space-y-2 text-xs text-slate-300">
              <p className="text-slate-200">Likely vector: {item.predicted_vector}</p>
              <p>{item.rationale}</p>
              {item.supporting_alerts?.length > 0 && (
                <p className="text-slate-500">Supporting alerts: {item.supporting_alerts.join(', ')}</p>
              )}
            </div>
          </li>
        ))}
      </ul>
    )}
  </section>
);

export default function ThreatForecastPage() {
  const {
    data,
    isLoading,
    isError,
    error,
    refetch,
    isFetching,
  } = useQuery({
    queryKey: ['threat-forecast'],
    queryFn: fetchForecast,
    refetchInterval: 60000,
  });

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <div className="space-y-1">
          <h1 className="text-3xl font-semibold text-slate-100">Threat Forecast</h1>
          <p className="text-sm text-slate-400">
            AI-assisted risk projections over the next 24 hours to stay ahead of emerging campaigns.
          </p>
        </div>
        <div className="flex items-center gap-3 text-xs text-slate-500">
          {isFetching && <span>Refreshing...</span>}
          <button
            type="button"
            onClick={() => refetch()}
            className="inline-flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-1.5 font-semibold text-slate-200 hover:bg-slate-800/60"
          >
            Refresh
          </button>
        </div>
      </header>

      {isLoading ? (
        <div className="rounded-3xl border border-slate-800/60 bg-slate-900/40 p-8 text-sm text-slate-400">
          Generating forecast from recent detections...
        </div>
      ) : isError ? (
        <div className="rounded-3xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-sm text-rose-100">
          {error?.response?.data?.detail?.message || error?.message || 'Failed to load threat forecast.'}
        </div>
      ) : !data ? (
        <EmptyState />
      ) : (
        <>
          <section className="grid gap-4 rounded-3xl border border-slate-800/70 bg-slate-900/60 p-6 md:grid-cols-4">
            <div className="space-y-1">
              <p className="text-xs uppercase tracking-wide text-slate-500">Risk index</p>
              <p className="text-3xl font-semibold text-slate-100">{data.risk_index?.toFixed?.(1) ?? data.risk_index}</p>
              <p className={`text-xs font-semibold ${trendStyles[data.trend_direction] || trendStyles.Stable}`}>
                {trendLabel(data.trend_direction)}
              </p>
            </div>
            <div className="space-y-2">
              <p className="text-xs uppercase tracking-wide text-slate-500">Confidence</p>
              <span className={`inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold ${confidenceStyles[data.overall_confidence] || confidenceStyles.Low}`}>
                {data.overall_confidence} confidence
              </span>
              <p className="text-[11px] text-slate-500">Generated at {formatDateTime(data.generated_at)}</p>
            </div>
            <div className="space-y-2 md:col-span-2">
              <p className="text-xs uppercase tracking-wide text-slate-500">Risk trend outlook</p>
              <div className="space-y-3">
                {data.risk_trends.map((point) => (
                  <div key={point.timestamp} className="space-y-1">
                    <div className="flex items-center justify-between text-[11px] text-slate-400">
                      <span>{new Date(point.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                      <span className="font-semibold text-slate-300">{point.risk_score}</span>
                    </div>
                    <RiskBar score={point.risk_score} />
                  </div>
                ))}
              </div>
            </div>
          </section>

          <div className="grid gap-6 lg:grid-cols-2">
            <EntityList
              title="High-risk assets"
              subtitle="Endpoints or IPs projected to experience malicious behaviour."
              items={data.high_risk_assets || []}
            />
            <EntityList
              title="High-risk subnets"
              subtitle="Network segments trending towards elevated threat levels."
              items={data.high_risk_subnets || []}
            />
          </div>
        </>
      )}
    </div>
  );
}
