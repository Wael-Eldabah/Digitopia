// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useEffect, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import axios from 'axios';
import { applyBlocklistSnapshot, isValidIpAddress } from '../utils/blocklist.js';

const SEARCH_STATE_KEY = 'eyeguard:ip-url-search';

const providerLabels = {
  virustotal: 'VirusTotal',
  otx: 'AlienVault OTX',
  abuseipdb: 'AbuseIPDB',
  shodan: 'Shodan',
};

export default function IPSearchPage() {
  const [ip, setIp] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const [blockError, setBlockError] = useState('');
  const [blockSuccess, setBlockSuccess] = useState('');
  const [urlValue, setUrlValue] = useState('');
  const [urlError, setUrlError] = useState('');
  const [urlResult, setUrlResult] = useState(null);
  const [urlLoading, setUrlLoading] = useState(false);
  const [searchHistory, setSearchHistory] = useState([]);

  const [blocking, setBlocking] = useState(false);
  const queryClient = useQueryClient();
  const formatTimestamp = (value) => {
    if (!value) {
      return 'Unknown';
    }
    try {
      return new Date(value).toLocaleString();
    } catch (error) {
      return String(value);
    }
  };

  const recordHistory = (entry) => {
    if (!entry || typeof entry.value !== 'string') {
      return;
    }
    const value = entry.value.trim();
    if (!value) {
      return;
    }
    const type = entry.type === 'URL' ? 'URL' : 'IP';
    setSearchHistory((prev) => {
      const current = Array.isArray(prev) ? prev : [];
      const filtered = current.filter((item) => !(item.type === type && item.value === value));
      const nextEntry = { type, value, timestamp: Date.now() };
      return [nextEntry, ...filtered].slice(0, 8);
    });
  };

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }
    try {
      const raw = window.localStorage.getItem(SEARCH_STATE_KEY);
      if (!raw) {
        return;
      }
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === 'object') {
        if (typeof parsed.ip === 'string') {
          setIp(parsed.ip);
        }
        if (typeof parsed.url === 'string') {
          setUrlValue(parsed.url);
        }
        if (Array.isArray(parsed.history)) {
          const sanitized = parsed.history
            .filter((item) => item && typeof item.type === 'string' && typeof item.value === 'string')
            .slice(0, 8);
          if (sanitized.length) {
            setSearchHistory(sanitized);
          }
        }
      }
    } catch (restoreError) {
      console.warn('Failed to restore search history', restoreError);
    }
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }
    try {
      const payload = {
        ip,
        url: urlValue,
        history: searchHistory,
      };
      window.localStorage.setItem(SEARCH_STATE_KEY, JSON.stringify(payload));
    } catch (persistError) {
      console.warn('Failed to persist search history', persistError);
    }
  }, [ip, urlValue, searchHistory]);

  const performIpSearch = async (candidate) => {
    const value = (candidate || '').trim();
    if (!value) {
      setError('Enter an IP address to search.');
      return;
    }
    setIp(value);
    setLoading(true);
    setError('');
    setBlockError('');
    setBlockSuccess('');
    setResult(null);
    try {
      const { data } = await axios.get('/api/search/ip', { params: { ip: value } });
      setResult({ ...data, blocked: data.blocked });
      recordHistory({ type: 'IP', value });
    } catch (err) {
      const message = err?.response?.data?.error || 'Lookup failed. Ensure the IP is valid.';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const performUrlSearch = async (candidate) => {
    const value = (candidate || '').trim();
    if (!value) {
      setUrlError('Enter a URL to search.');
      return;
    }
    setUrlValue(value);
    setUrlLoading(true);
    setUrlError('');
    setUrlResult(null);
    try {
      const { data } = await axios.get('/api/search/indicator', { params: { value, indicator_type: 'url' } });
      setUrlResult(data);
      recordHistory({ type: 'URL', value });
    } catch (err) {
      const message = err?.response?.data?.error || 'URL lookup failed. Ensure the value is valid.';
      setUrlError(message);
    } finally {
      setUrlLoading(false);
    }
  };

  const addIpToBlocklist = async (value) => {
    const normalized = (value || '').trim();
    if (!normalized) {
      throw new Error('IP address required.');
    }
    if (!isValidIpAddress(normalized)) {
      throw new Error('Enter a valid IPv4 or IPv6 address.');
    }
    const { data } = await axios.post('/api/blocklist', { ip: normalized });
    applyBlocklistSnapshot(queryClient, data);
    queryClient.invalidateQueries({ queryKey: ['blocklist'], exact: false });
    queryClient.invalidateQueries({ queryKey: ['blocked-ips'], exact: false });
    return normalized;
  };
  const handleHistoryClick = (entry) => {
    if (!entry || typeof entry.value !== 'string') {
      return;
    }
    if (entry.type === 'URL') {
      performUrlSearch(entry.value);
    } else {
      performIpSearch(entry.value);
    }
  };

  const clearHistory = () => {
    setSearchHistory([]);
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    await performIpSearch(ip);
  };

  const handleUrlSubmit = async (event) => {
    event.preventDefault();
    await performUrlSearch(urlValue);
  };

  const handleBlockIp = async () => {
    if (!result || typeof result.ip !== 'string') {
      setBlockSuccess('');
      setBlockError('No IP selected.');
      return;
    }
    if (result.blocked) {
      setBlockSuccess('');
      setBlockError('IP address is already blocked.');
      return;
    }
    setBlocking(true);
    setBlockError('');
    setBlockSuccess('');
    try {
      const normalized = await addIpToBlocklist(result.ip);
      setResult((prev) => (prev ? { ...prev, blocked: true } : prev));
      setBlockSuccess(`IP ${normalized} added to blocklist.`);
    } catch (err) {
      const message = err?.response?.data?.detail?.error
        || err?.response?.data?.detail?.message
        || err?.response?.data?.error
        || (err instanceof Error ? err.message : null)
        || 'Failed to block IP.';
      setBlockError(message);
    } finally {
      setBlocking(false);
    }
  };
  const hasRecentAlerts = Array.isArray(result?.recent_alerts) && result.recent_alerts.length > 0;
  const hasRelatedDevices = Array.isArray(result?.related_devices) && result.related_devices.length > 0;
  const hasActivity = Array.isArray(result?.activity_log) && result.activity_log.length > 0;
  const resolvedIps = Array.isArray(result?.resolved_ips) ? result.resolved_ips : [];
  const historyHasItems = Array.isArray(searchHistory) && searchHistory.length > 0;
  const shodanSummary = result?.shodan_summary || '';
  const shodanRisk = typeof result?.shodan_risk === 'number' ? result.shodan_risk : null;

const renderProviderCard = (provider, payload) => {
  const name = providerLabels[provider] || provider;
  const details = payload && typeof payload === 'object' ? payload : {};
  const data = details.data && typeof details.data === 'object' ? details.data : {};
  const summaryText = typeof data.summary === 'string'
    ? data.summary
    : typeof details.summary === 'string'
      ? details.summary
      : 'No summary available.';
  const extras = [];

  if (provider === 'virustotal') {
    const malicious = data.malicious_count ?? data.malicious ?? data.last_analysis_stats?.malicious;
    const suspicious = data.suspicious_count ?? data.suspicious ?? data.last_analysis_stats?.suspicious;
    if (typeof malicious === 'number') {
      extras.push(`Malicious detections: ${malicious}`);
    }
    if (typeof suspicious === 'number') {
      extras.push(`Suspicious detections: ${suspicious}`);
    }
  } else if (provider === 'otx') {
    const pulses = data.pulse_count ?? data.count ?? (Array.isArray(data.pulses) ? data.pulses.length : undefined);
    if (typeof pulses === 'number') {
      extras.push(`Pulse count: ${pulses}`);
    }
  } else if (provider === 'abuseipdb') {
    if (typeof data.abuse_score === 'number') {
      extras.push(`Abuse confidence: ${data.abuse_score}`);
    }
    if (typeof data.total_reports === 'number') {
      extras.push(`Total reports: ${data.total_reports}`);
    }
  } else if (provider === 'shodan') {
    const ports = Array.isArray(data.ports) ? data.ports.slice(0, 5) : [];
    if (ports.length) {
      extras.push(`Ports: ${ports.join(', ')}`);
    }
    const tags = Array.isArray(data.tags) ? data.tags.slice(0, 5) : [];
    if (tags.length) {
      extras.push(`Tags: ${tags.join(', ')}`);
    }
    if (typeof data.risk === 'number') {
      extras.push(`Exposure score: ${data.risk}`);
    }
  }

  const showExtras = extras.length > 0;
  const rawData = JSON.stringify(data, null, 2);

  return (
    <div key={provider} className="bg-slate-900/70 border border-slate-800 rounded-2xl p-4 space-y-2 text-sm">
      <div className="flex items-center justify-between">
        <h3 className="text-slate-100 font-semibold">{name}</h3>
        <span className="text-xs text-slate-500 uppercase">Source</span>
      </div>
      <p className="text-xs text-slate-300">Summary: {summaryText}</p>
      {showExtras && (
        <ul className="text-xs text-slate-400 space-y-1">
          {extras.map((item) => (
            <li key={`${provider}-${item}`}>{item}</li>
          ))}
        </ul>
      )}
      <details className="text-xs text-slate-500">
        <summary className="cursor-pointer text-slate-400">View payload</summary>
        <pre className="mt-2 bg-slate-950/80 border border-slate-800/70 rounded-xl p-3 overflow-x-auto text-[11px] text-slate-300">
          {rawData}
        </pre>
      </details>
    </div>
  );
};

  const severityTone = (value) => {
    const label = String(value || '').toLowerCase();
    if (label === 'critical') {
      return 'text-rose-200';
    }
    if (label === 'high') {
      return 'text-rose-300';
    }
    if (label === 'medium') {
      return 'text-amber-200';
    }
    if (label === 'low') {
      return 'text-emerald-200';
    }
    return 'text-slate-100';
  };

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold text-slate-100">IP Reputation Search</h1>
        <p className="text-sm text-slate-400">Query simulated threat intelligence sources and review aggregated outcomes.</p>
      </header>
      <section className="bg-[#101b30] border border-slate-800/70 rounded-3xl p-6 shadow-[0_25px_60px_rgba(8,17,32,0.55)]">
        <div className="flex items-center justify-between gap-3">
          <h2 className="text-lg font-semibold text-slate-100">Previous Searches</h2>
          {historyHasItems && (
            <button
              type="button"
              onClick={clearHistory}
              className="text-xs font-semibold text-slate-400 transition hover:text-slate-200"
            >
              Clear
            </button>
          )}
        </div>
        {historyHasItems ? (
          <div className="mt-4 flex flex-wrap gap-2">
            {searchHistory.map((entry) => (
              <button
                key={`${entry.type}-${entry.value}`}
                type="button"
                onClick={() => handleHistoryClick(entry)}
                className="flex items-center gap-2 rounded-xl border border-slate-700 px-3 py-1.5 text-xs text-slate-200 transition hover:bg-slate-800/60"
              >
                <span className={`rounded-lg border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${entry.type === 'URL' ? 'bg-violet-500/20 text-violet-200 border-violet-500/40' : 'bg-sky-500/20 text-sky-200 border-sky-500/40'}`}>
                  {entry.type}
                </span>
                <span className="font-mono text-sm text-slate-100">{entry.value}</span>
              </button>
            ))}
          </div>
        ) : (
          <p className="mt-3 text-xs text-slate-500">Search activity will appear here.</p>
        )}
      </section>
      <form onSubmit={handleSubmit} className="bg-[#101b30] border border-slate-800/70 rounded-3xl p-6 flex flex-col md:flex-row gap-4 shadow-[0_25px_60px_rgba(8,17,32,0.55)]">
        <input
          type="text"
          value={ip}
          onChange={(event) => setIp(event.target.value)}
          placeholder="e.g. 198.51.100.24"
          className="flex-1 bg-slate-900/70 border border-slate-800 rounded-xl px-4 py-3 text-sm text-slate-200 focus:border-sky-500 focus:ring-2 focus:ring-sky-500/30"
        />
        <button
          type="submit"
          disabled={loading}
          className="md:w-auto w-full px-6 py-3 rounded-xl bg-sky-500/90 text-slate-950 font-semibold text-sm hover:bg-sky-400 transition disabled:opacity-60"
        >
          {loading ? 'Searching...' : 'Search'}
        </button>
      </form>
      <form onSubmit={handleUrlSubmit} className="bg-[#101b30] border border-slate-800/70 rounded-3xl p-6 flex flex-col md:flex-row gap-4 shadow-[0_25px_60px_rgba(8,17,32,0.55)]">
        <input
          type="text"
          value={urlValue}
          onChange={(event) => setUrlValue(event.target.value)}
          placeholder="https://example.com/malware"
          className="flex-1 bg-slate-900/70 border border-slate-800 rounded-xl px-4 py-3 text-sm text-slate-200 focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/30"
        />
        <button
          type="submit"
          disabled={urlLoading}
          className="md:w-auto w-full px-6 py-3 rounded-xl bg-emerald-500/90 text-slate-950 font-semibold text-sm hover:bg-emerald-400 transition disabled:opacity-60"
        >
          {urlLoading ? 'Searching URL...' : 'Search URL'}
        </button>
      </form>
      {error && (
        <div className="border border-rose-500/40 bg-rose-500/10 rounded-2xl px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
      )}
      {urlError && (
        <div className="border border-rose-500/40 bg-rose-500/10 rounded-2xl px-4 py-3 text-sm text-rose-200">
          {urlError}
        </div>
      )}
      {urlResult && (
        <section className="bg-[#0d172a] border border-slate-800/70 rounded-3xl p-6 space-y-4 shadow-[0_25px_60px_rgba(8,17,32,0.55)]">
          <div className="flex items-start justify-between">
            <div>
              <h2 className="text-xl font-semibold text-slate-100">URL Intelligence</h2>
              <p className="text-xs uppercase tracking-widest text-slate-500">{urlResult.value}</p>
            </div>
            {urlResult.missing_api_keys?.length > 0 && (
              <span className="text-xs font-semibold text-amber-300 bg-amber-500/10 px-3 py-1 rounded-full">
                Missing API keys: {urlResult.missing_api_keys.join(', ')}
              </span>
            )}
          </div>
          {urlResult.intel_summary && (
            <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-4 text-sm text-slate-200">
              <p className="text-xs uppercase tracking-wider text-slate-500 mb-1">Intel Summary</p>
              <p>{urlResult.intel_summary}</p>
            </div>
          )}
          {urlResult.malicious_sources?.length ? (
            <div className="flex flex-wrap gap-2">
              {urlResult.malicious_sources.map((source) => (
                <span key={source} className="inline-flex items-center rounded-full border border-rose-500/40 bg-rose-500/10 px-3 py-1 text-[11px] uppercase tracking-wide text-rose-200">
                  {source}
                </span>
              ))}
            </div>
          ) : null}
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <h3 className="text-sm font-semibold text-slate-100">Resolved IPs</h3>
              {urlResult.resolved_ips.length ? (
                <ul className="space-y-1 text-xs text-slate-300">
                  {urlResult.resolved_ips.map((entry) => (
                    <li key={entry} className="bg-slate-950/60 border border-slate-800 rounded-xl px-3 py-2">{entry}</li>
                  ))}
                </ul>
              ) : (
                <p className="text-xs text-slate-500">No additional IPs resolved.</p>
              )}
            </div>
            <div className="space-y-2">
              <h3 className="text-sm font-semibold text-slate-100">Aggregated Summary</h3>
              <pre className="text-xs text-slate-400 bg-slate-950/80 border border-slate-800/70 rounded-xl p-3 overflow-x-auto">
                {JSON.stringify(urlResult.aggregated_summary, null, 2)}
              </pre>
            </div>
          </div>
          <div className="grid md:grid-cols-3 gap-4">
            {Object.entries(urlResult.source_results || {}).map(([provider, payload]) => (
              <div key={provider} className="bg-slate-900/70 border border-slate-800 rounded-2xl p-4 space-y-2 text-sm">
                <div className="flex items-center justify-between">
                  <h4 className="text-slate-100 font-semibold">{providerLabels[provider] || provider}</h4>
                  <span className="text-xs text-slate-500 uppercase">Source</span>
                </div>
                <pre className="text-xs text-slate-400 bg-slate-950/80 border border-slate-800/70 rounded-xl p-3 overflow-x-auto">
                  {JSON.stringify((payload && payload.data) ? payload.data : payload, null, 2)}
                </pre>
              </div>
            ))}
          </div>
        </section>
      )}

      {result && (
        <div className="grid xl:grid-cols-[2fr_1fr] gap-6">
          <section className="bg-[#0d172a] border border-slate-800/70 rounded-3xl p-6 space-y-4 shadow-[0_25px_60px_rgba(8,17,32,0.55)]">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-xl font-semibold text-slate-100">Aggregated Summary</h2>
                <p className="text-xs uppercase tracking-widest text-slate-500">{result.ip}</p>
              </div>
              {result.missing_api_keys?.length > 0 && (
                <span className="text-xs font-semibold text-amber-300 bg-amber-500/10 px-3 py-1 rounded-full">
                  Missing API keys: {result.missing_api_keys.join(', ')}
                </span>
              )}
            </div>
            {result.computed_verdict && (
              <div className={`mt-3 rounded-2xl border px-4 py-3 text-sm ${result.computed_verdict.severity === 'High' ? 'border-rose-500/40 bg-rose-500/10 text-rose-200' : 'border-sky-500/40 bg-sky-500/10 text-sky-100'}`}>
                <p className="font-semibold">Severity: {result.computed_verdict.severity}</p>
                <p>Recommended action: {result.computed_verdict.action}</p>
                {result.verdict_rationale && <p className="mt-1 text-[13px]">{result.verdict_rationale}</p>}
              </div>
            )}
            {result.computed_verdict?.severity === 'High' && (
              <div className="mt-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                <span className="text-sm text-rose-200">This IP is considered malicious.</span>
                {result.blocked ? (
                  <span className="text-xs text-emerald-300">Already on blocklist</span>
                ) : (
                  <button
                    type="button"
                    onClick={handleBlockIp}
                    className="px-4 py-2 rounded-xl bg-rose-500/80 text-slate-950 text-xs font-semibold hover:bg-rose-400 transition disabled:opacity-60"
                    disabled={blocking}
                  >
                    {blocking ? 'Blocking...' : 'Block this IP'}
                  </button>
                )}
              </div>
            )}

{blockSuccess && <p className="mt-2 text-xs text-emerald-300">{blockSuccess}</p>}
{blockError && <p className="mt-2 text-xs text-rose-400">{blockError}</p>}
{result.intel_summary && (
  <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-4 text-sm text-slate-200">
    <p className="text-xs uppercase tracking-wider text-slate-500 mb-1">Analyst Note</p>
    <p>{result.intel_summary}</p>
  </div>
)}
{result.malicious_sources?.length ? (
  <div className="flex flex-wrap gap-2">
    {result.malicious_sources.map((source) => (
      <span key={source} className="inline-flex items-center rounded-full border border-rose-500/40 bg-rose-500/10 px-3 py-1 text-[11px] uppercase tracking-wide text-rose-200">
        {source}
      </span>
    ))}
  </div>
) : null}
<p className="text-sm text-slate-300 leading-relaxed bg-slate-900/60 border border-slate-800/60 rounded-2xl p-4">
  {result.aggregated_summary}
</p>
            <div className="grid md:grid-cols-3 gap-4">
              {Object.entries(result.source_results || {}).map(([provider, payload]) => (
                <div key={provider} className="bg-slate-900/70 border border-slate-800 rounded-2xl p-4 space-y-2 text-sm">
                  <div className="flex items-center justify-between">
                    <h3 className="text-slate-100 font-semibold">{providerLabels[provider] || provider}</h3>
                    <span className="text-xs text-slate-500 uppercase">Source</span>
                  </div>
                  <pre className="text-xs text-slate-400 bg-slate-950/80 border border-slate-800/70 rounded-xl p-3 overflow-x-auto">
                    {JSON.stringify(payload.data, null, 2)}
                  </pre>
                </div>
              ))}
            </div>
            {(hasRecentAlerts || hasRelatedDevices) && (
              <div className="grid gap-4 md:grid-cols-2 mt-4">
                {hasRecentAlerts && (
                  <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-4 space-y-2">
                    <h4 className="text-sm font-semibold text-slate-100">Related Alerts</h4>
                    <ul className="space-y-2 text-xs text-slate-300">
                      {result.recent_alerts.slice(0, 5).map((entry, index) => (
                        <li key={entry.id || index} className="border border-slate-800/60 rounded-xl p-3 bg-slate-950/40">
                          <p className="font-semibold text-slate-100 text-sm">{entry.category}</p>
                          <p className="text-slate-400">{formatTimestamp(entry.detected_at)} - {entry.severity}</p>
                          {entry.playbook && <p className="text-slate-500">Playbook: {entry.playbook}</p>}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {hasRelatedDevices && (
                  <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-4 space-y-2">
                    <h4 className="text-sm font-semibold text-slate-100">Related Devices</h4>
                    <ul className="space-y-2 text-xs text-slate-300">
                      {result.related_devices.slice(0, 5).map((device, index) => (
                        <li key={device.id || device.ip_address || index} className="border border-slate-800/60 rounded-xl p-3 bg-slate-950/40">
                          <p className="font-semibold text-slate-100 text-sm">{device.hostname || 'Unidentified Host'}</p>
                          <p className="text-slate-400">IP: {device.ip_address}</p>
                          <p className="text-slate-500">Status: {device.status || 'unknown'}</p>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
            {hasActivity && (
              <div className="bg-slate-900/70 border border-slate-800 rounded-2xl p-4 space-y-3 mt-4">
                <h4 className="text-sm font-semibold text-slate-100">Activity Timeline</h4>
                <ol className="space-y-2 text-xs text-slate-300">
                  {result.activity_log.map((entry, index) => {
                    const context = entry?.metadata && typeof entry.metadata === 'object'
                      ? entry.metadata.indicator || entry.metadata.ip || entry.metadata.target || ''
                      : '';
                    return (
                      <li key={entry.id || index} className="border border-slate-800/60 rounded-xl p-3 bg-slate-950/40">
                        <span className="text-slate-400">{formatTimestamp(entry.created_at)} - {entry.event}</span>
                        {context && <span className="block text-slate-500">Context: {context}</span>}
                      </li>
                    );
                  })}
                </ol>
              </div>
            )}
          </section>
          <section className="bg-[#0d172a] border border-slate-800/70 rounded-3xl p-6 space-y-4 shadow-[0_25px_60px_rgba(8,17,32,0.55)]">
            <h2 className="text-lg font-semibold text-slate-100">Quick Facts</h2>
            <ul className="space-y-3 text-sm text-slate-300">
              <li>
                <span className="text-slate-500">IP Address:</span>
                <span className="ml-2 font-semibold text-slate-100">{result.ip}</span>
              </li>
              <li>
                <span className="text-slate-500">Providers Queried:</span>
                <span className="ml-2 font-semibold text-slate-100">{Object.keys(result.source_results || {}).length}</span>
              </li>
              <li>
                <span className="text-slate-500">Cache TTL:</span>
                <span className="ml-2 text-slate-300">5 minutes</span>
              </li>
              <li>
                <span className="text-slate-500">Severity:</span>
                <span className={`ml-2 font-semibold ${severityTone(result?.computed_verdict?.severity)}`}>
                  {result?.computed_verdict?.severity || 'N/A'}
                </span>
              </li>
              <li>
                <span className="text-slate-500">Blocklisted:</span>
                <span className="ml-2 font-semibold text-slate-100">{result?.blocked ? 'Yes' : 'No'}</span>
              </li>
              <li>
                <span className="text-slate-500">Resolved IPs:</span>
                <span className="ml-2 text-slate-300">{resolvedIps.length ? resolvedIps.join(', ') : 'None observed'}</span>
              </li>
              <li>
                <span className="text-slate-500">Telemetry Sources:</span>
                <span className="ml-2 text-slate-300">{result?.malicious_sources?.length ? result.malicious_sources.join(', ') : 'No positive matches'}</span>
              </li>
              <li>
                <span className="text-slate-500">Missing Keys:</span>
                <span className="ml-2 text-slate-300">{result?.missing_api_keys?.length ? result.missing_api_keys.join(', ') : 'None'}</span>
              </li>
              <li>
                <span className="text-slate-500">Shodan Summary:</span>
                <span className="ml-2 text-slate-300">{shodanSummary || 'No exposure detected'}</span>
              </li>
              <li>
                <span className="text-slate-500">Shodan Risk Score:</span>
                <span className={`ml-2 font-semibold ${shodanRisk && shodanRisk >= 70 ? 'text-rose-300' : 'text-slate-200'}`}>{shodanRisk !== null ? shodanRisk : 'N/A'}</span>
              </li>
            </ul>
          </section>
        </div>
      )}



    </div>
  );
}



