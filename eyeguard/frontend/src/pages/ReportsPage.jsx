// Software-only simulation / demo — no real systems will be contacted or modified.
import React from 'react';
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

export default function ReportsPage() {
  const { data: reports = [], isLoading } = useQuery({ queryKey: ['reports'], queryFn: fetchReports });

  return (
    <div className="space-y-6">
      <header>
        <h2 className="text-2xl font-semibold">Reports</h2>
        <p className="text-sm text-slate-400">Narratives, remediation steps, and export controls.</p>
      </header>
      <div className="bg-slate-900 border border-slate-800 rounded-xl">
        <div className="p-4 border-b border-slate-800">
          <h3 className="text-lg font-semibold">Incident Reports</h3>
        </div>
        {isLoading ? (
          <div className="p-6 text-sm text-slate-500">Loading reports...</div>
        ) : (
          <ul className="divide-y divide-slate-800">
            {reports.map((report) => (
              <li key={report.id} className="p-4 flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium">{report.summary}</p>
                  <p className="text-xs text-slate-500">Alert: {report.alert_id}</p>
                </div>
                <div className="flex gap-2">
                  <button
                    type="button"
                    className="bg-indigo-500 hover:bg-indigo-600 text-white text-xs px-3 py-2 rounded"
                    onClick={() => downloadFile(`/api/v1/reports/${report.id}/export.pdf`)}
                  >
                    Export PDF
                  </button>
                  <button
                    type="button"
                    className="bg-emerald-500 hover:bg-emerald-600 text-white text-xs px-3 py-2 rounded"
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
    </div>
  );
}
