// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useState } from 'react';
import axios from 'axios';

const providerLabels = {
  virustotal: 'VirusTotal',
  otx: 'AlienVault OTX',
  abuseipdb: 'AbuseIPDB',
};

export default function IPSearchPage() {
  const [ip, setIp] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!ip.trim()) {
      setError('Enter an IP address to search.');
      return;
    }
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const { data } = await axios.get('/api/search/ip', { params: { ip } });
      setResult(data);
    } catch (err) {
      const message = err?.response?.data?.error || 'Lookup failed. Ensure the IP is valid.';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold text-slate-100">IP Reputation Search</h1>
        <p className="text-sm text-slate-400">Query simulated threat intelligence sources and review aggregated outcomes.</p>
      </header>
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
      {error && (
        <div className="border border-rose-500/40 bg-rose-500/10 rounded-2xl px-4 py-3 text-sm text-rose-200">
          {error}
        </div>
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
                <span className="text-slate-500">Missing Keys:</span>
                <span className="ml-2 text-slate-300">{result.missing_api_keys?.length ? result.missing_api_keys.join(', ') : 'None'}</span>
              </li>
            </ul>
          </section>
        </div>
      )}
    </div>
  );
}
