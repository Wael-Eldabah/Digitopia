// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import axios from 'axios';

import { emptyBlocklistSnapshot, isValidIpAddress, normalizeBlocklistPayload, toComparableIp, applyBlocklistSnapshot } from '../utils/blocklist.js';

const ACTIVE_JOB_KEY = 'pcap.activeJobId';
const PENDING_REPORT_KEY = 'pcap.pendingReportRef';

const capitalizeWords = (value = '') =>
  value.replace(/(^|[\s-_])(\w)/g, (match) => match.toUpperCase());


const severityBadge = (severity) => {
  const level = (severity || '').toUpperCase();
  if (level === 'CRITICAL') {
    return 'bg-rose-600/25 text-rose-100 border border-rose-500/50';
  }
  if (level === 'HIGH') {
    return 'bg-rose-500/20 text-rose-200 border border-rose-500/40';
  }
  if (level === 'MEDIUM') {
    return 'bg-amber-500/20 text-amber-100 border border-amber-500/40';
  }
  if (level === 'LOW') {
    return 'bg-emerald-500/20 text-emerald-100 border border-emerald-500/40';
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

const formatSelfCheckKey = (label) => {
  if (!label) {
    return '';
  }
  return capitalizeWords(label.replace(/_/g, ' '));
};

const formatStageLabel = (value) => {
  if (!value) {
    return '';
  }
  return capitalizeWords(value.replace(/[-_]/g, ' '));
};

export default function PcapAnalysisPage() {
  const queryClient = useQueryClient();
  const [file, setFile] = useState(null);
  const fileInputRef = useRef(null);
  const [uploadError, setUploadError] = useState('');
  const [uploadSummary, setUploadSummary] = useState(null);
  const [activeJobId, setActiveJobId] = useState('');
  const [jobInitializedByUpload, setJobInitializedByUpload] = useState(false);
  const [lastJobStatus, setLastJobStatus] = useState(null);
  const [selectedAnalysisId, setSelectedAnalysisId] = useState('');

  const [blockedInput, setBlockedInput] = useState('');
  const [blockedError, setBlockedError] = useState('');
  const [blockedSuccess, setBlockedSuccess] = useState('');
  const [showBlockedPopover, setShowBlockedPopover] = useState(false);
  const blockedPopoverRef = useRef(null);

  const analysesQuery = useQuery({
    queryKey: ['pcap-analyses'],
    queryFn: async () => {
      const { data } = await axios.get('/api/pcap/analyses');
      return data;
    },
    refetchOnWindowFocus: 'always',
    refetchIntervalInBackground: true,
    staleTime: 5000,
  });

  const detailQuery = useQuery({
    queryKey: ['pcap-analysis', selectedAnalysisId],
    queryFn: async () => {
      const { data } = await axios.get(`/api/pcap/analyses/${selectedAnalysisId}`);
      return data;
    },
    enabled: Boolean(selectedAnalysisId),
  });

  const jobQuery = useQuery({
    queryKey: ['pcap-job', activeJobId],
    queryFn: async () => {
      const { data } = await axios.get(`/api/pcap/jobs/${activeJobId}`);
      return data;
    },
    enabled: Boolean(activeJobId),
    refetchInterval: activeJobId ? 2500 : false,
    refetchIntervalInBackground: Boolean(activeJobId),
    refetchOnWindowFocus: 'always',
  });

  const blockedIpsQuery = useQuery({
    queryKey: ['blocked-ips'],
    queryFn: async () => {
      const { data } = await axios.get('/api/blocklist');
      return normalizeBlocklistPayload(data);
    },
    refetchInterval: 10000,
    refetchIntervalInBackground: true,
    staleTime: 5000,
    placeholderData: emptyBlocklistSnapshot,
  });

  const uploadMutation = useMutation({
    mutationFn: async (formData) => {
      const payload = formData instanceof FormData ? formData : formData?.formData;
      if (!(payload instanceof FormData)) {
        throw new Error('No PCAP payload provided.');
      }
      const { data } = await axios.post('/api/pcap/upload', payload, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      return data;
    },
    onMutate: () => {
      setUploadError('');
      setUploadSummary(null);
      setJobInitializedByUpload(true);
    },
    onSuccess: (jobStatus) => {
      setActiveJobId(jobStatus.id);
      setLastJobStatus(jobStatus);
      setFile(null);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    },
    onError: (err) => {
      const message = err?.response?.data?.detail?.error || err?.response?.data?.detail?.message || err?.message || 'PCAP upload failed.';
      setUploadError(message);
      setJobInitializedByUpload(false);
    },
  });

  const blockIpMutation = useMutation({
    mutationFn: async (ip) => {
      const { data } = await axios.post('/api/blocklist', { ip });
      return data;
    },
    onSuccess: (payload) => {
      applyBlocklistSnapshot(queryClient, payload);
      queryClient.invalidateQueries({ queryKey: ['blocklist'], exact: false });
      queryClient.invalidateQueries({ queryKey: ['blocked-ips'], exact: false });
      setBlockedInput('');
      setBlockedError('');
      setBlockedSuccess('IP blocked successfully.');
    },
    onError: (error) => {
      const detail = error?.response?.data?.detail;
      const message =
        (detail && (detail.error || detail.message)) ||
        error?.message ||
        'Unable to block IP.';
      setBlockedError(message);
      setBlockedSuccess('');
    },
  });
  const unblockIpMutation = useMutation({
    mutationFn: async (ip) => {
      const { data } = await axios.delete(`/api/blocklist/${encodeURIComponent(ip)}`);
      return data;
    },
    onSuccess: (payload) => {
      applyBlocklistSnapshot(queryClient, payload);
      queryClient.invalidateQueries({ queryKey: ['blocklist'], exact: false });
      queryClient.invalidateQueries({ queryKey: ['blocked-ips'], exact: false });
      setBlockedInput('');
      setBlockedError('');
      setBlockedSuccess('IP unblocked successfully.');
    },
    onError: (error) => {
      const detail = error?.response?.data?.detail;
      const message =
        (detail && (detail.error || detail.message)) ||
        error?.message ||
        'Unable to unblock IP.';
      setBlockedError(message);
      setBlockedSuccess('');
    },
  });
  const isMutatingBlocklist = blockIpMutation.isPending || unblockIpMutation.isPending;
  const blocklistSnapshot = blockedIpsQuery.data ?? emptyBlocklistSnapshot;
  const blocklistItems = Array.isArray(blocklistSnapshot?.items) ? blocklistSnapshot.items : [];
  const blocklistDetails = Array.isArray(blocklistSnapshot?.details) ? blocklistSnapshot.details : [];

  const blocklistSet = useMemo(() => {
    const normalized = new Set();
    blocklistItems.forEach((ip) => {
      if (typeof ip === 'string') {
        const comparable = toComparableIp(ip);
        if (comparable) {
          normalized.add(comparable);
        }
      }
    });
    return normalized;
  }, [blocklistItems]);

  const blocklistEntries = useMemo(() => {
    const hydrated = blocklistDetails
      .map((entry) => {
        if (!entry || typeof entry.ip !== 'string') {
          return null;
        }
        const ipValue = entry.ip.trim();
        if (!ipValue.length) {
          return null;
        }
        const createdAtDate =
          typeof entry.created_at === 'string' && entry.created_at
            ? new Date(entry.created_at)
            : null;
        const createdAtValid =
          createdAtDate && !Number.isNaN(createdAtDate.getTime()) ? createdAtDate : null;
        const createdAtLabel = createdAtValid
          ? createdAtValid.toLocaleTimeString([], {
              hour: '2-digit',
              minute: '2-digit',
              second: '2-digit',
            })
          : null;
        return {
          ip: ipValue,
          createdAt: createdAtValid,
          createdAtLabel,
        };
      })
      .filter(Boolean);

    const existingIps = new Set(hydrated.map((item) => item.ip));
    blocklistItems.forEach((item) => {
      if (typeof item !== 'string') {
        return;
      }
      const ipValue = item.trim();
      if (ipValue && !existingIps.has(ipValue)) {
        hydrated.push({
          ip: ipValue,
          createdAt: null,
          createdAtLabel: null,
        });
      }
    });

    hydrated.sort((a, b) => {
      const aTime = a.createdAt ? a.createdAt.getTime() : 0;
      const bTime = b.createdAt ? b.createdAt.getTime() : 0;
      return bTime - aTime;
    });
    return hydrated;
  }, [blocklistDetails, blocklistItems]);

  const blockedCount = blocklistEntries.length;
  const blockedSample = blocklistEntries.slice(0, 12);
  const blockedOverflow = Math.max(0, blockedCount - blockedSample.length);
  const isBlockedListUpdating = blockedIpsQuery.isFetching || isMutatingBlocklist;


  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }
    try {
      const storedJobId = window.sessionStorage.getItem(ACTIVE_JOB_KEY);
      if (storedJobId) {
        setActiveJobId((prev) => prev || storedJobId);
        setJobInitializedByUpload(true);
      }
      const storedReport = window.sessionStorage.getItem(PENDING_REPORT_KEY);
      if (storedReport) {
        try {
          const parsed = JSON.parse(storedReport);
          if (parsed?.reportRef) {
            setSelectedAnalysisId((prev) => prev || parsed.reportRef);
          }
        } catch (parseError) {
          window.sessionStorage.removeItem(PENDING_REPORT_KEY);
        }
      }
    } catch (storageError) {
      // ignore storage errors
    }
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }
    try {
      if (activeJobId) {
        window.sessionStorage.setItem(ACTIVE_JOB_KEY, activeJobId);
      } else {
        window.sessionStorage.removeItem(ACTIVE_JOB_KEY);
      }
    } catch (storageError) {
      // ignore storage errors
    }
  }, [activeJobId]);

  useEffect(() => {
    if (!selectedAnalysisId || !detailQuery.data || typeof window === 'undefined') {
      return;
    }
    try {
      const stored = window.sessionStorage.getItem(PENDING_REPORT_KEY);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed?.reportRef === selectedAnalysisId) {
          window.sessionStorage.removeItem(PENDING_REPORT_KEY);
        }
      }
    } catch (storageError) {
      // ignore storage errors
    }
  }, [selectedAnalysisId, detailQuery.data]);

  useEffect(() => {
    if (!showBlockedPopover) {
      return;
    }
    const handleClickOutside = (event) => {
      if (blockedPopoverRef.current && !blockedPopoverRef.current.contains(event.target)) {
        setShowBlockedPopover(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [showBlockedPopover]);

  useEffect(() => {
    if (!jobQuery.data) {
      return;
    }
    const status = String(jobQuery.data.status || '').toLowerCase();
    if (['completed', 'failed'].includes(status)) {
      setLastJobStatus(jobQuery.data);
      if (status === 'completed' && jobQuery.data.report_ref) {
        setUploadSummary({
          report_ref: jobQuery.data.report_ref,
          alerts_generated: jobQuery.data.alerts_generated,
          blocked_ips: jobQuery.data.blocked_ips || [],
          self_check: jobQuery.data.self_check || {},
        });
        setSelectedAnalysisId(jobQuery.data.report_ref);
        try {
          if (typeof window !== 'undefined') {
            window.sessionStorage.setItem(
              PENDING_REPORT_KEY,
              JSON.stringify({ reportRef: jobQuery.data.report_ref, ts: Date.now() })
            );
          }
        } catch (storageError) {
          // ignore storage errors
        }
        queryClient.invalidateQueries({ queryKey: ['pcap-analyses'] });
        queryClient.invalidateQueries({ queryKey: ['blocked-ips'] });
      } else if (status === 'completed') {
        queryClient.invalidateQueries({ queryKey: ['blocked-ips'] });
      }
      setJobInitializedByUpload(false);
      setActiveJobId('');
    } else {
      setLastJobStatus(jobQuery.data);
    }
  }, [jobQuery.data, queryClient]);

  const sortedAnalyses = useMemo(() => {
    if (!analysesQuery.data) {
      return [];
    }
    return [...analysesQuery.data].sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
  }, [analysesQuery.data]);

  const handleManualBlock = () => {
    const value = blockedInput.trim();
    setBlockedSuccess('');
    if (!value) {
      setBlockedError('Enter an IP address.');
      return;
    }
    if (!isValidIpAddress(value)) {
      setBlockedError('Enter a valid IPv4 or IPv6 address.');
      return;
    }
    if (blocklistSet.has(toComparableIp(value))) {
      setBlockedError('IP address is already blocked.');
      return;
    }
    setBlockedError('');
    blockIpMutation.mutate(value);
  };

  const handleManualUnblock = () => {
    const value = blockedInput.trim();
    setBlockedSuccess('');
    if (!value) {
      setBlockedError('Enter an IP address.');
      return;
    }
    if (!isValidIpAddress(value)) {
      setBlockedError('Enter a valid IPv4 or IPv6 address.');
      return;
    }
    if (!blocklistSet.has(toComparableIp(value))) {
      setBlockedError('IP address is not currently blocked.');
      return;
    }
    setBlockedError('');
    unblockIpMutation.mutate(value);
  };

  const handleUploadSubmit = async (event) => {
    event.preventDefault();
    if (!file) {
      setUploadError('Select a PCAP file to analyze.');
      return;
    }
    const formData = new FormData();
    formData.append('file', file);
    uploadMutation.mutate(formData);
  };


  const jobStatusData = jobQuery.data || lastJobStatus;
  const jobStatusLabel = String(jobStatusData?.status || '').toLowerCase();
  const jobStatusDisplay = jobStatusLabel
    ? capitalizeWords(jobStatusLabel)
    : jobStatusData
      ? 'Queued'
      : null;
  const jobStatusDetail = jobStatusData?.message || formatStageLabel(jobStatusData?.stage);
  const jobSelfCheckEntries = Object.entries(jobStatusData?.self_check || {});
  const showSelfCheck = jobStatusLabel === 'completed' && jobSelfCheckEntries.length > 0;
  const jobBlockedIps = Array.isArray(jobStatusData?.blocked_ips) ? jobStatusData.blocked_ips : [];
  const showJobStatus = jobInitializedByUpload || Boolean(jobStatusData);

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
              setUploadError('');
            }}
            className="flex-1 text-sm text-slate-200 file:mr-4 file:rounded-lg file:border-0 file:bg-sky-500/80 file:px-4 file:py-2 file:text-slate-900 hover:file:bg-sky-400"
          />
          <button
            type="submit"
            className="px-5 py-2 rounded-xl bg-sky-500/80 text-slate-950 text-sm font-semibold hover:bg-sky-400 transition disabled:opacity-60"
            disabled={uploadMutation.isPending}
          >
            {uploadMutation.isPending ? 'Uploading…' : 'Analyze PCAP'}
          </button>
        </form>
        {uploadError && <p className="text-sm text-rose-400">{uploadError}</p>}
        {showJobStatus && (
          <div className="space-y-2 text-xs text-slate-400">
            <div className="flex items-center justify-between">
              <span className="uppercase tracking-wide text-[11px] text-slate-500">Analysis Status</span>
              <span>{jobStatusDisplay || 'Queued'}</span>
            </div>
            {jobStatusDetail && (
              <p className="text-[11px] text-slate-500">{jobStatusDetail}</p>
            )}
            {showSelfCheck && (
              <div className="space-y-1 rounded-lg border border-slate-800/60 bg-slate-900/40 p-3">
                <p className="text-[10px] uppercase tracking-wider text-slate-500">Self-check</p>
                <ul className="space-y-1 text-[11px]">
                  {jobSelfCheckEntries.map(([key, value]) => {
                    const passed = Boolean(value);
                    return (
                      <li key={key} className="flex items-center justify-between gap-2">
                        <span className="text-slate-400">{formatSelfCheckKey(key)}</span>
                        <span className={passed ? 'text-emerald-400' : 'text-rose-400'}>
                          {passed ? 'Passed' : 'Failed'}
                        </span>
                      </li>
                    );
                  })}
                </ul>
              </div>
            )}
            {jobBlockedIps.length > 0 && (
              <div className="rounded-lg border border-slate-800/60 bg-slate-900/40 p-3">
                <p className="text-[10px] uppercase tracking-wider text-slate-500">Blocked IPs</p>
                <p className="text-[11px] text-slate-300">{jobBlockedIps.join(', ')}</p>
              </div>
            )}
          </div>
        )}
        {uploadSummary && (
          <div className="space-y-3 border border-slate-800 rounded-2xl p-4 bg-slate-900/60">
            <div className="flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
              <h3 className="text-sm font-semibold text-slate-100">Latest Analysis</h3>
              <span className="text-xs text-slate-500">Report Ref: {uploadSummary.report_ref}</span>
            </div>
            <div className="grid md:grid-cols-3 gap-3 text-xs text-slate-300">
              <div className="bg-slate-950/60 border border-slate-800 rounded-xl px-3 py-2">
                <p className="text-[11px] uppercase text-slate-500">Alerts Generated</p>
                <p className="text-slate-100 text-sm">{uploadSummary.alerts_generated ?? 0}</p>
              </div>
              <div className="bg-slate-950/60 border border-slate-800 rounded-xl px-3 py-3 relative">
                <div className="flex items-center justify-between text-[11px] uppercase text-slate-500">
                  <span>Blocked IPs</span>
                  {blockedIpsQuery.isFetching && (
                    <span className="text-[10px] text-slate-600">Updating...</span>
                  )}
                </div>
                <button
                  type="button"
                  onClick={() => setShowBlockedPopover((prev) => !prev)}
                  className="mt-2 w-full flex items-center justify-between rounded-lg border border-slate-700 bg-slate-900/40 px-3 py-2 text-sm text-slate-100 hover:border-sky-400 hover:text-sky-200 transition"
                >
                  <span className="font-semibold">{blockedCount}</span>
                  <span className="text-slate-500 text-xs">?</span>
                </button>
                {showBlockedPopover && (
                  <div ref={blockedPopoverRef} className="absolute left-3 right-3 top-full mt-2 z-30">
                    <div className="rounded-xl border border-slate-800 bg-[#0d162a] shadow-xl shadow-slate-900/40 max-h-56 overflow-y-auto p-3 space-y-2">
                      {blockedSample.length ? (
                        <ul className="space-y-1 text-xs text-slate-200">
                          {blockedSample.map((entry) => (
                            <li key={entry.ip} className="flex items-center justify-between gap-2">
                              <span className="font-mono">{entry.ip}</span>
                              {entry.createdAtLabel && (
                                <span className="text-[10px] text-slate-500">{entry.createdAtLabel}</span>
                              )}
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="text-xs text-slate-500">No IPs currently blocked.</p>
                      )}
                      {blockedOverflow > 0 && (
                        <p className="text-[10px] text-slate-500">+ {blockedOverflow} more hidden</p>
                      )}
                    </div>
                  </div>
                )}
                <input
                  type="text"
                  value={blockedInput}
                  onChange={(event) => {
                    setBlockedInput(event.target.value);
                    if (blockedError) {
                      setBlockedError('');
                    }
                    if (blockedSuccess) {
                      setBlockedSuccess('');
                    }
                  }}
                  placeholder="Enter IP address"
                  className="mt-3 w-full rounded-lg border border-slate-800/70 bg-slate-900/60 px-3 py-2 text-xs text-slate-200 focus:border-emerald-400/60 focus:outline-none focus:ring-1 focus:ring-emerald-400/40"
                  autoComplete="off"
                />
                <div className="mt-2 flex gap-2">
                  <button
                    type="button"
                    onClick={handleManualBlock}
                    disabled={isMutatingBlocklist}
                    className="w-full rounded-lg border border-emerald-500/60 px-3 py-2 text-xs font-semibold text-emerald-200 transition hover:bg-emerald-500/20 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {blockIpMutation.isPending ? 'Blocking...' : 'Block IP'}
                  </button>
                  <button
                    type="button"
                    onClick={handleManualUnblock}
                    disabled={isMutatingBlocklist}
                    className="w-full rounded-lg border border-rose-500/60 px-3 py-2 text-xs font-semibold text-rose-200 transition hover:bg-rose-500/20 disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {unblockIpMutation.isPending ? 'Unblocking...' : 'Unblock IP'}
                  </button>
                </div>
                {blockedError && (
                  <p className="mt-2 text-[11px] text-rose-300">{blockedError}</p>
                )}
                {blockedSuccess && !blockedError && (
                  <p className="mt-2 text-[11px] text-emerald-300">{blockedSuccess}</p>
                )}
              </div>
              <div className="bg-slate-950/60 border border-slate-800 rounded-xl px-3 py-2">
                <p className="text-[11px] uppercase text-slate-500">Self-checks</p>
                <p className="text-slate-100 text-sm">{jobSelfCheckEntries.length}</p>
              </div>
            </div>
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
                        {alert.indicator} - {alert.message}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {detailQuery.data.ips?.length > 0 && renderIpTable(detailQuery.data.ips)}
              {renderDetectionSection(detailQuery.data)}
              {renderDnsSection(detailQuery.data)}
              {renderTlsSection(detailQuery.data)}
            </div>
          )}
        </section>
      )}
    </div>
  );
}

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


const renderDetectionSection = (analysis) => {
  const detectionMap = analysis.detections || analysis.summary?.detections || {};
  const detectionKeys = Object.keys(detectionMap || {});
  if (!detectionKeys.length) {
    return null;
  }
  const labels = {
    beaconing: 'Beaconing Patterns',
    bruteforce: 'Brute-force Activity',
    port_scans: 'Port Scans',
    exfiltration: 'Possible Exfiltration',
    dns_anomaly: 'DNS Anomalies',
  };
  return (
    <section className="space-y-2">
      <h4 className="text-xs uppercase tracking-wide text-slate-400">Detections</h4>
      <div className="space-y-3">
        {detectionKeys.map((key) => {
          const entries = detectionMap[key] || [];
          if (!entries.length) {
            return null;
          }
          return (
            <div key={key} className="rounded-xl border border-slate-800 bg-slate-950/60 p-3 text-xs text-slate-300">
              <p className="text-[11px] uppercase text-slate-500 mb-2">{labels[key] || key.replace(/_/g, ' ')}</p>
              <ul className="space-y-1">
                {entries.map((entry, index) => renderDetectionEntry(key, entry, index))}
              </ul>
            </div>
          );
        })}
      </div>
    </section>
  );
};

const renderDetectionEntry = (type, entry, index) => {
  const identifier = entry?.ip || entry?.source_ip || entry?.target || entry?.service || index;
  const key = `${type}-${identifier}`;
  if (type === 'beaconing') {
    const meanInterval = typeof entry.mean_interval === 'number' ? entry.mean_interval.toFixed(2) : entry.mean_interval;
    return (
      <li key={key} className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-slate-200">{entry.source_ip || entry.ip || 'Unknown'}</span>
        <span className="text-slate-500">{'->'} {entry.target || 'target'}</span>
        <span className="text-slate-400">{entry.packet_count || 0} packets</span>
        {meanInterval && (
          <span className="text-slate-500">mean {meanInterval}s</span>
        )}
      </li>
    );
  }
  if (type === 'bruteforce') {
    const perMin = typeof entry.per_min === 'number' ? entry.per_min.toFixed(1) : entry.per_min;
    return (
      <li key={key} className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-slate-200">{entry.ip || 'Unknown'}</span>
        <span className="text-slate-400">service {entry.service || 'n/a'}</span>
        <span className="text-slate-500">attempts {entry.attempts || 0}</span>
        {perMin && <span className="text-slate-500">~{perMin}/min</span>}
      </li>
    );
  }
  if (type === 'port_scans') {
    return (
      <li key={key} className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-slate-200">{entry.ip || 'Unknown'}</span>
        <span className="text-slate-500">ports {entry.distinct_ports || 0}</span>
        {entry.attempts_per_5min && (
          <span className="text-slate-500">{entry.attempts_per_5min} attempts/5min</span>
        )}
      </li>
    );
  }
  if (type === 'exfiltration') {
    return (
      <li key={key} className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-slate-200">{entry.ip || 'Unknown'}</span>
        <span className="text-slate-500">outbound {formatBytes(entry.bytes_out || 0)}</span>
      </li>
    );
  }
  if (type === 'dns_anomaly') {
    return (
      <li key={key} className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-slate-200">{entry.ip || 'Unknown'}</span>
        <span className="text-slate-500">queries {entry.queries || 0}</span>
        <span className="text-slate-500">unique {entry.unique_domains || entry.unique || 0}</span>
        {entry.high_entropy !== undefined && (
          <span className="text-slate-500">high entropy {entry.high_entropy}</span>
        )}
      </li>
    );
  }
  return (
    <li key={key} className="text-slate-400">{JSON.stringify(entry)}</li>
  );
};

const renderDnsSection = (analysis) => {
  const dnsActivity = analysis.dns_activity || analysis.summary?.dns_activity || [];
  if (!dnsActivity.length) {
    return null;
  }
  return (
    <section className="space-y-2">
      <h4 className="text-xs uppercase tracking-wide text-slate-400">DNS Activity</h4>
      <div className="overflow-x-auto border border-slate-800 rounded-2xl">
        <table className="min-w-full divide-y divide-slate-800 text-xs">
          <thead className="bg-slate-900/70 text-slate-400 uppercase">
            <tr>
              <th className="px-3 py-2 text-left">Domain</th>
              <th className="px-3 py-2 text-left">Total</th>
              <th className="px-3 py-2 text-left">Sources</th>
              <th className="px-3 py-2 text-left">Flags</th>
              <th className="px-3 py-2 text-left">First Seen</th>
              <th className="px-3 py-2 text-left">Last Seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 text-slate-200">
            {dnsActivity.map((entry) => {
              const sources = Array.isArray(entry.sources) ? entry.sources : [];
              const displaySources = sources.slice(0, 3).join(', ');
              const sourceOverflow = Math.max(0, sources.length - 3);
              const flags = [];
              if (entry.high_entropy) {
                flags.push('high entropy');
              }
              if (entry.long_name) {
                flags.push('long name');
              }
              return (
                <tr key={entry.domain}>
                  <td className="px-3 py-2 font-mono">{entry.domain}</td>
                  <td className="px-3 py-2">{entry.count || 0}</td>
                  <td className="px-3 py-2">
                    {displaySources || 'n/a'}
                    {sourceOverflow > 0 && (
                      <span className="ml-1 text-slate-500">+{sourceOverflow}</span>
                    )}
                  </td>
                  <td className="px-3 py-2">{flags.length ? flags.join(', ') : 'none'}</td>
                  <td className="px-3 py-2">{formatDate(entry.first_seen_iso || entry.first_seen)}</td>
                  <td className="px-3 py-2">{formatDate(entry.last_seen_iso || entry.last_seen)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
};

const renderTlsSection = (analysis) => {
  const tlsSummary = analysis.tls_summary || analysis.summary?.tls_summary || [];
  if (!tlsSummary.length) {
    return null;
  }
  return (
    <section className="space-y-2">
      <h4 className="text-xs uppercase tracking-wide text-slate-400">TLS Handshakes</h4>
      <div className="overflow-x-auto border border-slate-800 rounded-2xl">
        <table className="min-w-full divide-y divide-slate-800 text-xs">
          <thead className="bg-slate-900/70 text-slate-400 uppercase">
            <tr>
              <th className="px-3 py-2 text-left">Client</th>
              <th className="px-3 py-2 text-left">Server</th>
              <th className="px-3 py-2 text-left">Port</th>
              <th className="px-3 py-2 text-left">SNI</th>
              <th className="px-3 py-2 text-left">Versions</th>
              <th className="px-3 py-2 text-left">Cipher</th>
              <th className="px-3 py-2 text-left">Packets</th>
              <th className="px-3 py-2 text-left">Bytes</th>
              <th className="px-3 py-2 text-left">Last Seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800 text-slate-200">
            {tlsSummary.slice(0, 20).map((entry, index) => {
              const versions = Array.isArray(entry.record_versions) ? entry.record_versions : [];
              const supported = Array.isArray(entry.supported_versions) ? entry.supported_versions : [];
              const cipherSuites = Array.isArray(entry.client_cipher_suites) ? entry.client_cipher_suites : [];
              return (
                <tr key={`${entry.client_ip || 'client'}-${entry.server_ip || 'server'}-${index}`}>
                  <td className="px-3 py-2 font-mono">{entry.client_ip || 'n/a'}</td>
                  <td className="px-3 py-2 font-mono">{entry.server_ip || 'n/a'}</td>
                  <td className="px-3 py-2">{entry.server_port || 'n/a'}</td>
                  <td className="px-3 py-2">{entry.sni || 'n/a'}</td>
                  <td className="px-3 py-2">{supported.length ? supported.join(', ') : versions.join(', ') || 'n/a'}</td>
                  <td className="px-3 py-2">{entry.selected_cipher || cipherSuites[0] || 'n/a'}</td>
                  <td className="px-3 py-2">{entry.packet_count || 0}</td>
                  <td className="px-3 py-2">{formatBytes(entry.byte_count || 0)}</td>
                  <td className="px-3 py-2">{formatDate(entry.last_seen_iso || entry.last_seen)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
};






