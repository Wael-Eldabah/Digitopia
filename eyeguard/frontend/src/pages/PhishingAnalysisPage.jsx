// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useMemo, useState } from 'react';
import axios from 'axios';

const confidenceBadge = (riskLevel) => {
  switch (riskLevel) {
    case 'High':
      return 'border border-rose-400/50 bg-rose-500/15 text-rose-100';
    case 'Medium':
      return 'border border-amber-400/40 bg-amber-500/15 text-amber-100';
    default:
      return 'border border-emerald-400/40 bg-emerald-500/15 text-emerald-100';
  }
};

const IndicatorList = ({ indicators }) => {
  if (!indicators?.length) {
    return (
      <p className="text-sm text-slate-400">
        No distinct phishing indicators were detected in this submission.
      </p>
    );
  }
  return (
    <ul className="space-y-3">
      {indicators.map((indicator) => (
        <li
          key={`${indicator.type}-${indicator.value}`}
          className="rounded-2xl border border-slate-800/60 bg-slate-900/60 p-4"
        >
          <p className="text-sm font-semibold text-slate-100">
            {indicator.type.replace('-', ' ')}
          </p>
          <p className="text-xs text-slate-400">{indicator.value}</p>
          {indicator.description && (
            <p className="mt-2 text-xs text-slate-500">{indicator.description}</p>
          )}
          <p className="mt-1 text-[11px] text-slate-500">Score impact: {indicator.score}</p>
        </li>
      ))}
    </ul>
  );
};

const KeyValueGrid = ({ title, data }) => {
  const entries = useMemo(() => Object.entries(data || {}), [data]);
  if (!entries.length) {
    return null;
  }
  return (
    <section className="space-y-3">
      {title && (
        <header>
          <h3 className="text-sm font-semibold text-slate-100">{title}</h3>
        </header>
      )}
      <div className="grid gap-3 text-xs text-slate-300 sm:grid-cols-2">
        {entries.map(([key, value]) => (
          <div key={key} className="rounded-xl border border-slate-800/60 bg-slate-900/50 p-3">
            <p className="uppercase tracking-wide text-[11px] text-slate-500">{key}</p>
            <pre className="mt-1 font-mono text-[11px] text-slate-300 whitespace-pre-wrap break-words">
              {typeof value === 'object' ? JSON.stringify(value, null, 2) : String(value)}
            </pre>
          </div>
        ))}
      </div>
    </section>
  );
};

export default function PhishingAnalysisPage() {
  const [rawEmail, setRawEmail] = useState('');
  const [label, setLabel] = useState('');
  const [createAlert, setCreateAlert] = useState(true);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setSubmitting(true);
    try {
      const { data } = await axios.post('/api/v1/phishing/analyze', {
        raw_email: rawEmail,
        create_alert: createAlert,
        label: label || undefined,
      });
      setResult(data);
    } catch (err) {
      const detail = err?.response?.data?.detail;
      const message = detail?.message || detail?.error || err?.message || 'Failed to analyze email headers.';
      setError(message);
      setResult(null);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold text-slate-100">Phishing Email Analysis</h1>
        <p className="text-sm text-slate-400">
          Submit raw email headers or full .eml contents to validate MX, SPF, DKIM, and transmission heuristics.
        </p>
      </header>

      <form onSubmit={handleSubmit} className="space-y-4 rounded-3xl border border-slate-800/70 bg-[#0d172a] p-6 shadow-[0_25px_60px_rgba(8,17,32,0.55)]">
        <div className="space-y-2">
          <label htmlFor="rawEmail" className="text-xs uppercase tracking-wide text-slate-500">
            Raw email (.eml or headers)
          </label>
          <textarea
            id="rawEmail"
            value={rawEmail}
            onChange={(event) => setRawEmail(event.target.value)}
            className="h-48 w-full rounded-xl border border-slate-800 bg-slate-950/60 px-3 py-3 text-sm text-slate-200 focus:border-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-500/30"
            placeholder="Paste the full raw email message or headers here..."
            required
          />
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <div className="space-y-1">
            <label htmlFor="label" className="text-xs uppercase tracking-wide text-slate-500">
              Label (optional)
            </label>
            <input
              id="label"
              value={label}
              onChange={(event) => setLabel(event.target.value)}
              className="w-full rounded-xl border border-slate-800 bg-slate-950/60 px-3 py-2 text-sm text-slate-200 focus:border-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-500/30"
              placeholder="e.g. Reported by user@example.com"
            />
          </div>
          <label className="flex items-center gap-2 text-xs text-slate-400">
            <input
              type="checkbox"
              checked={createAlert}
              onChange={(event) => setCreateAlert(event.target.checked)}
              className="h-4 w-4 rounded border border-slate-600 bg-slate-900 text-sky-500 focus:ring-2 focus:ring-sky-500/50"
            />
            Create an alert when risk score ≥ Medium
          </label>
        </div>

        {error && (
          <p className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-3 py-2 text-xs text-rose-100">
            {error}
          </p>
        )}

        <button
          type="submit"
          className="inline-flex items-center justify-center rounded-xl bg-sky-500 px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-sky-400 disabled:cursor-not-allowed disabled:opacity-60"
          disabled={submitting}
        >
          {submitting ? 'Analyzing…' : 'Analyze Email'}
        </button>
      </form>

      {result && (
        <section className="space-y-6 rounded-3xl border border-slate-800/70 bg-[#101b30] p-6 shadow-[0_20px_50px_rgba(7,15,30,0.45)]">
          <header className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
            <div className="space-y-1">
              <h2 className="text-xl font-semibold text-slate-100">Risk Summary</h2>
              <p className="text-sm text-slate-400">{result.summary}</p>
              {result.mx_findings && (
                <p className="text-[11px] text-slate-500 uppercase tracking-wide">
                  MXToolbox mode:{' '}
                  {(() => {
                    const findings = result.mx_findings;
                    const mode = findings.mode || findings.status;
                    if (mode === 'no-key') {
                      return findings.issues?.[0] || 'No key configured';
                    }
                    if (mode === 'lookup-error') {
                      return 'Live lookup unavailable; heuristics applied';
                    }
                    if (findings.status && findings.status !== 'mocked') {
                      return findings.status;
                    }
                    return 'Live';
                  })()}
                </p>
              )}
            </div>
            <div className="flex flex-col items-start gap-2 sm:items-end">
              <span className={`inline-flex items-center rounded-full px-3 py-1 text-xs font-semibold ${confidenceBadge(result.risk_level)}`}>
                {result.risk_level} risk
              </span>
              <span className="text-xs text-slate-400">Score: {result.risk_score}/100</span>
              {result.alerts_created?.length > 0 && (
                <p className="text-[11px] text-emerald-300">
                  Alerts created: {result.alerts_created.join(', ')}
                </p>
              )}
            </div>
          </header>

          <section className="space-y-3">
            <h3 className="text-sm font-semibold text-slate-100">Phishing indicators</h3>
            <IndicatorList indicators={result.indicators} />
          </section>

          <KeyValueGrid title="Authentication & header heuristics" data={result.heuristics} />

          {result.mx_findings && (
            <KeyValueGrid title="MXToolbox findings" data={result.mx_findings} />
          )}

          {result.suggested_actions?.length > 0 && (
            <section className="space-y-2">
              <h3 className="text-sm font-semibold text-slate-100">Suggested actions</h3>
              <ul className="list-disc space-y-1 pl-5 text-xs text-slate-300">
                {result.suggested_actions.map((action) => (
                  <li key={action}>{action}</li>
                ))}
              </ul>
            </section>
          )}
        </section>
      )}
    </div>
  );
}
