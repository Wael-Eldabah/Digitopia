// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useMemo, useState } from 'react';
import axios from 'axios';
import { useQuery } from '@tanstack/react-query';

const fetchReports = async () => {
  const response = await axios.get('/api/v1/reports');
  return response.data;
};

const downloadFile = async (url) => {
  const response = await axios.get(url, { responseType: 'blob' });
  const blob = new Blob([response.data]);
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = url.endsWith('.pdf') ? 'report.pdf' : 'report.csv';
  link.click();
  URL.revokeObjectURL(link.href);
};

const normalizeSummary = (summary) => {
  if (!summary) {
    return 'No summary available.';
  }
  if (typeof summary === 'string') {
    return summary;
  }
  if (summary.description) {
    return summary.description;
  }
  if (summary.summary_text) {
    return summary.summary_text;
  }
  const entries = Object.entries(summary)
    .filter(([, value]) => typeof value !== 'object')
    .map(([key, value]) => `${key}: ${value}`);
  return entries.length ? entries.join(', ') : 'Summary data provided.';
};

export default function ReportsPage() {
  const { data: reports = [], isLoading } = useQuery({ queryKey: ['reports'], queryFn: fetchReports });
  const [selectedReport, setSelectedReport] = useState(null);
  const [detailState, setDetailState] = useState({ loading: false, error: '', data: null });

  const sortedReports = useMemo(
    () => [...reports].sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0)),
    [reports],
  );

  const handleViewDetails = async (report) => {
    setSelectedReport(report);
    setDetailState((prev) => ({ ...prev, loading: true, error: '', data: null }));
    try {
      const { data } = await axios.get(`/api/v1/reports/${report.id}`);
      setDetailState({ loading: false, error: '', data });
    } catch (error) {
      const message = error?.response?.data?.detail?.message || 'Failed to load report details.';
      setDetailState({ loading: false, error: message, data: null });
    }
  };

  const handleCloseDetails = () => {
    setSelectedReport(null);
    setDetailState({ loading: false, error: '', data: null });
  };

  return (
    <div className="space-y-6">
      <header>
        <h2 className="text-2xl font-semibold">Reports</h2>
        <p className="text-sm text-slate-400">Narratives, remediation steps, and export controls.</p>
      </header>
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <h3 className="text-lg font-semibold text-slate-100">Incident Reports</h3>
          <span className="text-xs text-slate-500">{sortedReports.length} report(s)</span>
        </div>
        {isLoading ? (
          <div className="p-6 text-sm text-slate-500">Loading reports...</div>
        ) : sortedReports.length === 0 ? (
          <div className="p-6 text-sm text-slate-500">No reports have been generated yet.</div>
        ) : (
          <ul className="divide-y divide-slate-800">
            {sortedReports.map((report) => (
              <li key={report.id} className="p-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
                <div className="space-y-1">
                  <p className="text-sm font-semibold text-slate-100">{report.title || `Report ${report.id}`}</p>
                  <p className="text-xs text-slate-400">{normalizeSummary(report.summary)}</p>
                  <p className="text-[11px] text-slate-500 uppercase tracking-wide">
                    {new Date(report.created_at || Date.now()).toLocaleString()}
                  </p>
                </div>
                <div className="flex flex-wrap gap-2 text-xs">
                  <button
                    type="button"
                    className="px-3 py-2 rounded border border-slate-700 text-slate-200 hover:border-sky-400 hover:text-sky-300 transition"
                    onClick={() => handleViewDetails(report)}
                  >
                    View Details
                  </button>
                  <button
                    type="button"
                    className="bg-indigo-500 hover:bg-indigo-600 text-white px-3 py-2 rounded"
                    onClick={() => downloadFile(`/api/v1/reports/${report.id}/export.pdf`)}
                  >
                    Export PDF
                  </button>
                  <button
                    type="button"
                    className="bg-emerald-500 hover:bg-emerald-600 text-white px-3 py-2 rounded"
                    onClick={() => downloadFile(`/api/v1/reports/${report.id}/export.csv`)}
                  >
                    Export CSV
                  </button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>

      {selectedReport && (
        <div className="bg-[#0e182b] border border-slate-800/70 rounded-3xl p-6 space-y-4 shadow-[0_25px_60px_rgba(8,17,32,0.55)]">
          <div className="flex items-start justify-between gap-4">
            <div>
              <h3 className="text-lg font-semibold text-slate-100">{selectedReport.title || 'Report details'}</h3>
              <p className="text-xs uppercase tracking-wide text-slate-500">Report ID: {selectedReport.id}</p>
            </div>
            <button
              type="button"
              className="text-xs text-slate-400 hover:text-slate-200 transition"
              onClick={handleCloseDetails}
            >
              Close
            </button>
          </div>
          {detailState.loading && <p className="text-sm text-slate-500">Loading details...</p>}
          {detailState.error && <p className="text-sm text-rose-400">{detailState.error}</p>}
          {detailState.data && (
            <div className="space-y-3">
              <div className="grid md:grid-cols-2 gap-3 text-sm">
                <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 space-y-1">
                  <p className="text-xs text-slate-500 uppercase">Summary</p>
                  <p className="text-slate-200 text-sm leading-relaxed">
                    {normalizeSummary(detailState.data.summary)}
                  </p>
                </div>
                <div className="bg-slate-900/70 border border-slate-800 rounded-xl p-4 space-y-1">
                  <p className="text-xs text-slate-500 uppercase">Indicators</p>
                  <ul className="text-slate-200 text-sm space-y-1">
                    {(detailState.data.indicators || []).map((indicator) => (
                      <li key={indicator}>{indicator}</li>
                    ))}
                  </ul>
                </div>
              </div>
              {detailState.data.payload && (
                <pre className="bg-slate-950/80 border border-slate-800 rounded-xl text-xs text-slate-400 p-4 overflow-x-auto">
                  {JSON.stringify(detailState.data.payload, null, 2)}
                </pre>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
