// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import axios from "axios";
import NetworkMap from "../components/NetworkMap.jsx";
import AlertsTable from "../components/AlertsTable.jsx";

import { emptyBlocklistSnapshot, isValidIpAddress, normalizeBlocklistPayload, toComparableIp, applyBlocklistSnapshot } from "../utils/blocklist.js";

const fetchDevices = async () => {
  const response = await axios.get("/api/v1/devices");
  return response.data;
};


export default function Dashboard() {
  const { data: devices = [], isLoading } = useQuery({
    queryKey: ["devices"],
    queryFn: fetchDevices,
    refetchInterval: 1000,
    staleTime: 15000,
  });

  const queryClient = useQueryClient();
  const [manualIp, setManualIp] = useState("");
  const [manualError, setManualError] = useState("");
  const [manualSuccess, setManualSuccess] = useState("");
  const [isListOpen, setIsListOpen] = useState(false);


  const metrics = useMemo(() => {
    if (!devices.length) {
      return {
        total: 0,
        blockedDevices: 0,
        online: 0,
        traffic: 0,
      };
    }
    const traffic = devices.reduce(
      (sum, device) => sum + (device.traffic_gb || 0),
      0,
    );
    return {
      total: devices.length,
      blockedDevices: devices.filter((device) => device.status === "blocked")
        .length,
      online: devices.filter((device) => device.status === "online").length,
      traffic,
    };
  }, [devices]);

  const {
    data: blocklistSnapshot = emptyBlocklistSnapshot,
    isFetching: blocklistFetching,
  } = useQuery({
    queryKey: ["blocklist"],
    queryFn: async () => {
      const { data } = await axios.get("/api/blocklist");
      return normalizeBlocklistPayload(data);
    },
    refetchInterval: 5000,
    staleTime: 4000,
    placeholderData: emptyBlocklistSnapshot,
  });
  const blockIpMutation = useMutation({
    mutationFn: async (ip) => {
      const { data } = await axios.post("/api/blocklist", { ip });
      return data;
    },
    onSuccess: (payload) => {
      applyBlocklistSnapshot(queryClient, payload);
      queryClient.invalidateQueries({ queryKey: ["blocklist"], exact: false });
      queryClient.invalidateQueries({ queryKey: ["blocked-ips"], exact: false });
      setManualIp("");
      setManualError("");
      setManualSuccess('IP blocked successfully.');
    },
    onError: (error) => {
      const detail = error?.response?.data?.detail;
      const message =
        (detail && (detail.error || detail.message)) ||
        error?.message ||
        "Unable to block IP.";
      setManualError(message);
      setManualSuccess('');
    },
  });

  const unblockIpMutation = useMutation({
    mutationFn: async (ip) => {
      const { data } = await axios.delete(`/api/blocklist/${encodeURIComponent(ip)}`);
      return data;
    },
    onSuccess: (payload) => {
      applyBlocklistSnapshot(queryClient, payload);
      queryClient.invalidateQueries({ queryKey: ["blocklist"], exact: false });
      queryClient.invalidateQueries({ queryKey: ["blocked-ips"], exact: false });
      setManualIp("");
      setManualError("");
      setManualSuccess('IP unblocked successfully.');
    },
    onError: (error) => {
      const detail = error?.response?.data?.detail;
      const message =
        (detail && (detail.error || detail.message)) ||
        error?.message ||
        "Unable to unblock IP.";
      setManualError(message);
      setManualSuccess('');
    },
  });

  const isMutatingBlocklist = blockIpMutation.isPending || unblockIpMutation.isPending;

  const blocklistItems = Array.isArray(blocklistSnapshot?.items) ? blocklistSnapshot.items : [];
  const blocklistCount =
    typeof blocklistSnapshot?.count === 'number' && Number.isFinite(blocklistSnapshot.count)
      ? blocklistSnapshot.count
      : blocklistItems.length;

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
    const detailSource = Array.isArray(blocklistSnapshot?.details)
      ? blocklistSnapshot.details
      : [];
    const hydrated = detailSource
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
          blocked_by: entry.blocked_by ?? null,
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
          blocked_by: null,
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
  }, [blocklistSnapshot?.details, blocklistItems]);

  const blocklistUpdatedAtLabel = useMemo(() => {
    if (!blocklistSnapshot?.updated_at) {
      return null;
    }
    const parsed = new Date(blocklistSnapshot.updated_at);
    if (Number.isNaN(parsed.getTime())) {
      return null;
    }
    return parsed.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }, [blocklistSnapshot?.updated_at]);

  const isBlocklistUpdating = blocklistFetching || isMutatingBlocklist;
  const blocklistCountDisplay = isBlocklistUpdating && !blocklistCount ? '--' : blocklistCount;
  const blocklistStatusLabel = isBlocklistUpdating
    ? 'UPDATING...'
    : blocklistUpdatedAtLabel
      ? `UPDATED ${blocklistUpdatedAtLabel}`
      : 'UPDATED';
  const blocklistStatusTone = isBlocklistUpdating ? 'text-sky-300 animate-pulse' : 'text-slate-500';

  const handleManualBlock = () => {
    const ipValue = manualIp.trim();
    setManualSuccess('');
    if (!ipValue) {
      setManualError('Enter an IP address.');
      return;
    }
    if (!isValidIpAddress(ipValue)) {
      setManualError('Enter a valid IPv4 or IPv6 address.');
      return;
    }
    if (blocklistSet.has(toComparableIp(ipValue))) {
      setManualError('IP address is already blocked.');
      return;
    }
    setManualError('');
    blockIpMutation.mutate(ipValue);
  };

  const handleManualUnblock = () => {
    const ipValue = manualIp.trim();
    setManualSuccess('');
    if (!ipValue) {
      setManualError('Enter an IP address.');
      return;
    }
    if (!isValidIpAddress(ipValue)) {
      setManualError('Enter a valid IPv4 or IPv6 address.');
      return;
    }
    if (!blocklistSet.has(toComparableIp(ipValue))) {
      setManualError('IP address is not currently blocked.');
      return;
    }
    setManualError('');
    unblockIpMutation.mutate(ipValue);
  };

  return (
    <div className="space-y-8 text-slate-100">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold tracking-tight">
          Operations Dashboard
        </h1>
        <p className="text-sm text-slate-400">
          Live network posture with real-time telemetry streaming from the
          EyeGuard sandbox.
        </p>
      </header>

      <section className="grid gap-6 xl:grid-cols-[2fr_1fr]">
        <div className="space-y-6">
          <div className="bg-[#0d172a] border border-slate-800/70 rounded-3xl p-6 shadow-[0_25px_60px_rgba(8,17,32,0.55)] space-y-6">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <div>
                <h2 className="text-xl font-semibold">
                  Network Intelligence Grid
                </h2>
                <p className="text-xs uppercase tracking-[0.35em] text-slate-500">
                  Device density vs. traffic throughput
                </p>
              </div>
              <span className="text-xs font-mono text-slate-500">
                Auto-refresh 1s
              </span>
            </div>
            <div className="min-h-[240px] w-full overflow-hidden rounded-2xl border border-slate-800/60 bg-slate-900/40">
              <NetworkMap devices={devices} />
              {isLoading && (
                <p className="p-4 text-center text-xs text-slate-500">
                  Loading devices...
                </p>
              )}
            </div>
          </div>

          <div className="bg-[#101b30] border border-slate-800/70 rounded-3xl p-6 space-y-4 shadow-[0_18px_50px_rgba(7,15,30,0.45)]">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <h3 className="text-lg font-semibold">Device Feed</h3>
              <span className="text-xs text-slate-500">Sorted by recency</span>
            </div>
            <ul className="space-y-3">
              {devices.map((device) => {
                const trendingUp = (device.traffic_delta ?? 0) >= 0;
                const delta = Math.abs(device.traffic_delta ?? 0).toFixed(2);
                const deltaSign = trendingUp ? "+" : "-";
                const directionLabel = trendingUp ? "UP" : "DOWN";
                const color = trendingUp
                  ? "text-emerald-300"
                  : "text-amber-300";
                return (
                  <li
                    key={device.id}
                    className="flex flex-col gap-3 bg-slate-900/60 border border-slate-800/60 rounded-2xl px-4 py-3 sm:flex-row sm:items-center sm:justify-between"
                  >
                    <div>
                      <p className="text-sm font-semibold text-slate-100">
                        {device.hostname}
                      </p>
                      <p className="text-xs text-slate-500 font-mono">
                        {device.ip_address}
                      </p>
                    </div>
                    <div className="text-left sm:text-right">
                      <p className="text-xs text-slate-500 uppercase">
                        Traffic
                      </p>
                      <p className={`text-sm font-semibold ${color}`}>
                        {device.traffic_gb.toFixed(2)} GB
                        <span className="ml-2 text-xs text-slate-400">
                          {directionLabel} {deltaSign}
                          {delta}
                        </span>
                      </p>
                    </div>
                  </li>
                );
              })}
              {!devices.length && (
                <li className="text-sm text-slate-500">
                  No devices registered yet.
                </li>
              )}
            </ul>
          </div>
        </div>

        <div className="flex flex-col gap-6">
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div className="bg-[#101b30] border border-slate-800/70 rounded-2xl p-4 shadow-inner shadow-slate-900/40">
              <p className="text-xs uppercase tracking-widest text-slate-500">
                Total Devices
              </p>
              <p className="mt-2 text-3xl font-semibold text-slate-100">
                {metrics.total}
              </p>
            </div>
            <div className="bg-[#101b30] border border-slate-800/70 rounded-2xl p-4 shadow-inner shadow-slate-900/40">
              <p className="text-xs uppercase tracking-widest text-slate-500">
                Online
              </p>
              <p className="mt-2 text-3xl font-semibold text-emerald-300">
                {metrics.online}
              </p>
            </div>
          </div>

          <div className="bg-[#101b30] border border-slate-800/70 rounded-2xl p-4 shadow-inner shadow-slate-900/40">
            <p className="text-xs uppercase tracking-widest text-slate-500">
              Total Traffic
            </p>
            <p className="mt-2 text-3xl font-semibold text-sky-300">
              {metrics.traffic.toFixed(1)} GB
            </p>
          </div>

          <div className="bg-[#101b30] border border-slate-800/70 rounded-2xl p-5 shadow-inner shadow-slate-900/40">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-center gap-2">
                <span className="inline-flex h-6 w-6 items-center justify-center rounded-full border border-slate-700 text-slate-300">
                  <svg
                    className="h-3.5 w-3.5"
                    viewBox="0 0 20 20"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.5"
                    aria-hidden="true"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h12M4 10h12M4 14h7" />
                  </svg>
                </span>
                <h3 className="text-sm font-semibold tracking-[0.4em] text-slate-400">
                  BLOCKED IPS
                </h3>
              </div>
              <span className={`text-[11px] font-semibold uppercase ${blocklistStatusTone}`}>
                {blocklistStatusLabel}
              </span>
            </div>
            <div className="mt-4 rounded-xl border border-slate-800/70 bg-slate-900/50 px-4 py-3">
              <p className="text-4xl font-semibold text-rose-300">{blocklistCountDisplay}</p>
              <p className="text-[11px] text-slate-500">IPs currently blocked</p>
            </div>
            <p className="mt-2 text-[11px] text-slate-500">
              Simulated devices blocked: {metrics.blockedDevices}
            </p>
            <label
              htmlFor="dashboard-blocklist-input"
              className="mt-4 block text-[11px] uppercase tracking-widest text-slate-500"
            >
              Enter IP address
            </label>
            <input
              id="dashboard-blocklist-input"
              type="text"
              value={manualIp}
              onChange={(event) => {
                setManualIp(event.target.value);
                if (manualError) {
                  setManualError('');
                }
                if (manualSuccess) {
                  setManualSuccess('');
                }
              }}
              placeholder="Enter IP address"
              className="mt-2 w-full rounded-xl border border-slate-800/70 bg-slate-900/70 px-3 py-2 text-sm text-slate-200 focus:border-emerald-400/60 focus:outline-none focus:ring-1 focus:ring-emerald-400/40"
              autoComplete="off"
            />
            <div className="mt-3 grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={handleManualBlock}
                disabled={isMutatingBlocklist}
                className="rounded-xl bg-emerald-500 px-3 py-2 text-sm font-semibold text-emerald-950 shadow-sm transition hover:bg-emerald-400 focus:outline-none focus:ring-2 focus:ring-emerald-400/60 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {blockIpMutation.isPending ? 'Blocking...' : 'Block IP'}
              </button>
              <button
                type="button"
                onClick={handleManualUnblock}
                disabled={isMutatingBlocklist}
                className="rounded-xl border border-rose-500/70 px-3 py-2 text-sm font-semibold text-rose-200 transition hover:bg-rose-500/10 focus:outline-none focus:ring-2 focus:ring-rose-500/40 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {unblockIpMutation.isPending ? 'Unblocking...' : 'Unblock IP'}
              </button>
            </div>
            {manualError && (
              <p className="mt-2 text-[11px] text-rose-300">{manualError}</p>
            )}
            {manualSuccess && !manualError && (
              <p className="mt-2 text-[11px] text-emerald-300">{manualSuccess}</p>
            )}
            <button
              type="button"
              onClick={() => setIsListOpen((previous) => !previous)}
              className="mt-4 inline-flex items-center gap-2 text-xs font-semibold text-slate-300 transition hover:text-slate-100 focus:outline-none"
            >
              <span>{isListOpen ? 'Hide' : 'View'} Blocked IPs List</span>
              <span className="inline-flex h-5 w-5 items-center justify-center rounded-full border border-slate-700 bg-slate-900/80 text-[11px] text-slate-200">
                {isListOpen ? '-' : '+'}
              </span>
              <span className="text-[10px] text-slate-500">{blocklistEntries.length}</span>
            </button>
            {isListOpen && (
              <div className="mt-3 rounded-xl border border-slate-800/70 bg-slate-900/40 p-3">
                <div className="flex items-center justify-between text-[11px] uppercase tracking-widest text-slate-500">
                  <span>Blocked IPs List</span>
                  <span className="text-[10px] text-slate-600">{blocklistCount} total</span>
                </div>
                <div className="mt-2 max-h-48 space-y-2 overflow-y-auto pr-1">
                  {blocklistEntries.length ? (
                    blocklistEntries.map((entry) => (
                      <div
                        key={entry.ip}
                        className="flex items-center justify-between gap-3 rounded-lg border border-slate-800/60 bg-slate-900/50 px-3 py-2"
                      >
                        <span className="truncate font-mono text-sm text-slate-100">{entry.ip}</span>
                        <button
                          type="button"
                          onClick={() => unblockIpMutation.mutate(entry.ip)}
                          disabled={isMutatingBlocklist}
                          className="rounded-lg border border-rose-500/70 px-3 py-1 text-xs font-semibold text-rose-200 transition hover:bg-rose-500/10 disabled:cursor-not-allowed disabled:opacity-60"
                        >
                          Unblock
                        </button>
                      </div>
                    ))
                  ) : (
                    <p className="text-[11px] text-slate-500">No IPs currently blocked.</p>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      </section>


      <section className="space-y-4">
        <h2 className="text-xl font-semibold">Active Alerts</h2>
        <AlertsTable />
      </section>
    </div>
  );
}










