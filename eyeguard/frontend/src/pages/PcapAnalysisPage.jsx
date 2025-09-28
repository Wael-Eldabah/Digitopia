// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useMemo, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import axios from 'axios';

const severityBadge = (severity) => {
  const level = (severity || '').toUpperCase();
  if (level === 'HIGH') {
    return 'bg-rose-500/20 text-rose-200 border border-rose-500/40';
  }
  if (level === 'MEDIUM') {
    return 'bg-amber-500/20 text-amber-100 border border-amber-500/40';
  }
  if (level === 'INFO') {
    return 'bg-sky-500/20 text-sky-100 border border-sky-500/40';
  }
  return 'bg-slate-800/60 text-slate-300 border border-slate-700/60';
};

const formatDate = (value) => {
  if (!value) {
    return 'Unknown';
  }
  try {
    return new Date(value).toLocaleString();
  } catch (error) {
    return String(value);
  }
};

const formatBytes = (bytes) => {
  if (typeof bytes !== 'number' || Number.isNaN(bytes)) {
    return '0 B';
  }
  if (bytes === 0) {
    return '0 B';
  }
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = bytes;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  const precision = value >= 10 || unitIndex === 0 ? 0 : 1;
  return `${value.toFixed(precision)} ${units[unitIndex]}`;
};

export default function PcapAnalysisPage() {
  const queryClient = useQueryClient();
  const [file, setFile] = useState(null);
  const fileInputRef = useRef(null);
  const [uploadProgress, setUploadProgress] = useState(null);
  const [uploadError, setUploadError] = useState('');
  const [uploadResult, setUploadResult] = useState(null);
  const [selectedAnalysisId, setSelectedAnalysisId] = useState('');

  const analysesQuery = useQuery({
    queryKey: ['pcap-analyses'],
    queryFn: async () => {
      const { data } = await axios.get('/api/pcap/analyses');
      return data;
    },
  });

  const detailQuery = useQuery({
    queryKey: ['pcap-analysis', selectedAnalysisId],
    queryFn: async () => {
      const { data } = await axios.get(`/api/pcap/analyses/${selectedAnalysisId}`);
      return data;
    },
    enabled: Boolean(selectedAnalysisId),
  });

  const uploadMutation = useMutation({
    mutationFn: async (payload) => {
      let formData;
      let fileSize = 0;
      if (payload instanceof FormData) {
        formData = payload;
        const candidate = payload.get('file');
        if (candidate && typeof candidate === 'object' && 'size' in candidate) {
          fileSize = Number(candidate.size) || 0;
        }
      } else if (payload && typeof payload === 'object') {
        ({ formData } = payload);
        fileSize = Number(payload.fileSize) || 0;
      }
      if (!(formData instanceof FormData)) {
        throw new Error('No PCAP payload provided.');
      }
      const { data } = await axios.post('/api/pcap/upload', formData, {
        onUploadProgress: (event) => {
          const total = event.total ?? fileSize ?? 0;
          const loaded = event.loaded ?? 0;
          const percent = total ? Math.min(100, Math.round((loaded / total) * 100)) : null;
          setUploadProgress({ loaded, total, percent });
        },
      });
      return data;
    },
    onMutate: () => {
      setUploadError('');
    },
    onSuccess: (data) => {
      setUploadResult(data);
      setSelectedAnalysisId('');
      setUploadProgress(null);
      setFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
      queryClient.invalidateQueries({ queryKey: ['pcap-analyses'] });
    },
    onError: (err) => {
      const message = err?.response?.data?.detail?.error || err?.response?.data?.detail?.message || err?.message || 'PCAP upload failed.';
      setUploadError(message);
      setUploadProgress(null);
    },
  });

  const sortedAnalyses = useMemo(() => {
    if (!analysesQuery.data) {
      return [];
    }
    return [...analysesQuery.data].sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
  }, [analysesQuery.data]);

  const handleUploadSubmit = async (event) => {
    event.preventDefault();
    if (!file) {
      setUploadError('Select a PCAP file to analyze.');
      return;
    }
    const formData = new FormData();
    formData.append('file', file);
    const totalBytes = typeof file.size === 'number' ? file.size : 0;
    setUploadProgress({ loaded: 0, total: totalBytes, percent: totalBytes ? 0 : null });
    uploadMutation.mutate({ formData, fileSize: totalBytes });
  };

  const renderIpTable = (ips) => (
    <div className="overflow-x-auto border border-slate-800 rounded-2xl">
      <table className="min-w-full divide-y divide-slate-800 text-sm">
        <thead className="bg-slate-900/70 text-slate-400 uppercase text-xs">
          <tr>
            <th className="px-4 py-3 text-left">IP Address</th>
            <th className="px-4 py-3 text-left">Packets</th>
            <th className="px-4 py-3 text-left">Severity</th>
            <th className="px-4 py-3 text-left">Summary</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800">
          {ips.map((entry) => (
            <tr key={entry.ip} className="text-slate-200">
              <td className="px-4 py-3 font-mono text-xs">{entry.ip}</td>
              <td className="px-4 py-3">{entry.packet_count}</td>
              <td className="px-4 py-3">
                <span className={`inline-flex items-center px-2 py-1 rounded-full text-[11px] font-semibold ${severityBadge(entry.severity)}`}>
                  {entry.severity}
                </span>
              </td>
              <td className="px-4 py-3 text-xs text-slate-400">
                {entry.aggregated_summary?.summary_text || 'No malicious telemetry.'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );

  return (
    <div className="space-y-6">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold text-slate-100">PCAP Analyzer</h1>
        <p className="text-sm text-slate-400">Upload packet captures, run threat intelligence checks, and review detailed findings.</p>
      </header>

      <section className="bg-[#101b30] border border-slate-800/70 rounded-3xl p-6 space-y-4 shadow-[0_25px_60px_rgba(8,17,32,0.55)]">
        <h2 className="text-lg font-semibold text-slate-100">Upload PCAP</h2>
        <form onSubmit={handleUploadSubmit} className="flex flex-col md:flex-row gap-4 md:items-center">
          <input
            ref={fileInputRef}
            type="file"
            accept=".pcap,.pcapng"
            onChange={(event) => {
              setFile(event.target.files?.[0] || null);
              setUploadProgress(null);
            }}
            className="flex-1 text-sm text-slate-200 file:mr-4 file:rounded-lg file:border-0 file:bg-sky-500/80 file:px-4 file:py-2 file:text-slate-900 hover:file:bg-sky-400"
          />
          <button
            type="submit"
            className="px-5 py-2 rounded-xl bg-sky-500/80 text-slate-950 text-sm font-semibold hover:bg-sky-400 transition disabled:opacity-60"
            disabled={uploadMutation.isPending}
          >
            {uploadMutation.isPending ? 'Analyzing...' : 'Analyze PCAP'}
          </button>
        </form>
        {(file || uploadProgress) && (
          <div className="space-y-2 text-xs text-slate-400">
            {file && (
              <div className="flex flex-wrap items-center justify-between gap-x-2">
                <span>Selected: {file.name}</span>
                <span>{formatBytes(typeof file.size === 'number' ? file.size : 0)}</span>
              </div>
            )}
            {uploadProgress && (
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <span className="uppercase tracking-wide text-[11px] text-slate-500">Uploading</span>
                  <span className="text-[11px] text-slate-400">
                    {uploadProgress.total
                      ? `${uploadProgress.percent ?? 0}% (${formatBytes(uploadProgress.loaded)} / ${formatBytes(uploadProgress.total)})`
                      : `${formatBytes(uploadProgress.loaded)} uploaded`}
                  </span>
                </div>
                <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden">
                  <div
                    className="h-full bg-sky-500 transition-all"
                    style={{ width: `${Math.min(100, uploadProgress.percent ?? 0)}%` }}
                  />
                </div>
              </div>
            )}
          </div>
        )}
        {uploadError && <p className="text-sm text-rose-400">{uploadError}</p>}
        {uploadResult && (
          <div className="space-y-3 border border-slate-800 rounded-2xl p-4 bg-slate-900/60">
            <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
              <h3 className="text-sm font-semibold text-slate-100">Latest Analysis</h3>
              <span className="text-xs text-slate-500">Report Ref: {uploadResult.report_ref}</span>
            </div>
            <div className="grid md:grid-cols-4 gap-3 text-xs text-slate-300">
              <div className="bg-slate-950/60 border border-slate-800 rounded-xl px-3 py-2">
                <p className="text-[11px] uppercase text-slate-500">Total Packets</p>
                <p className="text-slate-100 text-sm">{uploadResult.summary?.total_packets ?? 0}</p>
              </div>
              <div className="bg-slate-950/60 border border-slate-800 rounded-xl px-3 py-2">
                <p className="text-[11px] uppercase text-slate-500">Unique IPs</p>
                <p className="text-slate-100 text-sm">{uploadResult.summary?.unique_ips ?? 0}</p>
              </div>
              <div className="bg-slate-950/60 border border-slate-800 rounded-xl px-3 py-2">
                <p className="text-[11px] uppercase text-slate-500">Malicious IPs</p>
                <p className="text-slate-100 text-sm">{uploadResult.summary?.malicious_ips ?? 0}</p>
              </div>
              <div className="bg-slate-950/60 border border-slate-800 rounded-xl px-3 py-2">
                <p className="text-[11px] uppercase text-slate-500">Alerts</p>
                <p className="text-slate-100 text-sm">{uploadResult.alerts_triggered?.length ?? 0}</p>
              </div>
            </div>
            {uploadResult.alerts_triggered?.length > 0 && (
              <div className="space-y-2">
                <p className="text-xs text-rose-200 font-semibold">Alerts generated:</p>
                <ul className="space-y-1 text-xs text-slate-300">
                  {uploadResult.alerts_triggered.map((alert) => (
                    <li key={alert.indicator}>
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full mr-2 ${severityBadge(alert.severity)}`}>
                        {alert.severity}
                      </span>
                      {alert.indicator} — {alert.message}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {uploadResult.ips?.length > 0 && renderIpTable(uploadResult.ips)}
          </div>
        )}
      </section>

      <section className="bg-[#0d172a] border border-slate-800/70 rounded-3xl p-6 space-y-4 shadow-[0_25px_60px_rgba(8,17,32,0.55)]">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold text-slate-100">Previous Analyses</h2>
          <span className="text-xs text-slate-500">{sortedAnalyses.length} captured</span>
        </div>
        {analysesQuery.isLoading ? (
          <p className="text-sm text-slate-500">Loading analyses...</p>
        ) : sortedAnalyses.length === 0 ? (
          <p className="text-sm text-slate-500">No analyses recorded yet.</p>
        ) : (
          <div className="overflow-x-auto border border-slate-800 rounded-2xl">
            <table className="min-w-full divide-y divide-slate-800 text-sm">
              <thead className="bg-slate-900/70 text-slate-400 uppercase text-xs">
                <tr>
                  <th className="px-4 py-3 text-left">Report</th>
                  <th className="px-4 py-3 text-left">Created</th>
                  <th className="px-4 py-3 text-left">Malicious IPs</th>
                  <th className="px-4 py-3 text-left">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {sortedAnalyses.map((analysis) => (
                  <tr key={analysis.id} className="text-slate-200">
                    <td className="px-4 py-3">
                      <div className="font-semibold text-sm text-slate-100">{analysis.summary?.description || analysis.source_file || analysis.id}</div>
                      <div className="text-[11px] text-slate-500">{analysis.source_file || 'Uploaded capture'}</div>
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400">{formatDate(analysis.created_at)}</td>
                    <td className="px-4 py-3">{analysis.summary?.malicious_ips ?? 0}</td>
                    <td className="px-4 py-3">
                      <button
                        type="button"
                        className="px-3 py-1.5 rounded-lg border border-slate-700 hover:border-sky-400 hover:text-sky-300 transition text-xs"
                        onClick={() => setSelectedAnalysisId(analysis.id)}
                      >
                        View Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {selectedAnalysisId && (
        <section className="bg-[#101b30] border border-slate-800/70 rounded-3xl p-6 space-y-4 shadow-[0_25px_60px_rgba(8,17,32,0.55)]">
          <div className="flex items-start justify-between">
            <div>
              <h3 className="text-lg font-semibold text-slate-100">Analysis Detail</h3>
              <p className="text-xs text-slate-500">Report ID: {selectedAnalysisId}</p>
            </div>
            <button
              type="button"
              className="text-xs text-slate-400 hover:text-slate-200 transition"
              onClick={() => setSelectedAnalysisId('')}
            >
              Close
            </button>
          </div>
          {detailQuery.isLoading && <p className="text-sm text-slate-500">Loading analysis...</p>}
          {detailQuery.error && <p className="text-sm text-rose-400">Unable to load analysis.</p>}
          {detailQuery.data && (
            <div className="space-y-4">
              <div className="grid md:grid-cols-4 gap-3 text-xs text-slate-300">
                <div className="bg-slate-950/60 border border-slate-800 rounded-xl px-3 py-2">
                  <p className="text-[11px] uppercase text-slate-500">Created</p>
                  <p className="text-slate-100 text-sm">{formatDate(detailQuery.data.created_at)}</p>
                </div>
                <div className="bg-slate-950/60 border border-slate-800 rounded-xl px-3 py-2">
                  <p className="text-[11px] uppercase text-slate-500">Malicious IPs</p>
                  <p className="text-slate-100 text-sm">{detailQuery.data.summary?.malicious_ips ?? 0}</p>
                </div>
                <div className="bg-slate-950/60 border border-slate-800 rounded-xl px-3 py-2">
                  <p className="text-[11px] uppercase text-slate-500">Unique IPs</p>
                  <p className="text-slate-100 text-sm">{detailQuery.data.summary?.unique_ips ?? 0}</p>
                </div>
                <div className="bg-slate-950/60 border border-slate-800 rounded-xl px-3 py-2">
                  <p className="text-[11px] uppercase text-slate-500">Source</p>
                  <p className="text-slate-100 text-sm">{detailQuery.data.source_file || 'Capture'}</p>
                </div>
              </div>
              {detailQuery.data.alerts?.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs uppercase tracking-wide text-rose-200">Alerts generated</h4>
                  <ul className="space-y-1 text-xs text-slate-300">
                    {detailQuery.data.alerts.map((alert) => (
                      <li key={alert.indicator}>
                        <span className={`inline-flex items-center px-2 py-0.5 rounded-full mr-2 ${severityBadge(alert.severity)}`}>
                          {alert.severity}
                        </span>
                        {alert.indicator} — {alert.message}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {detailQuery.data.ips?.length > 0 && renderIpTable(detailQuery.data.ips)}
            </div>
          )}
        </section>
      )}
    </div>
  );
}
