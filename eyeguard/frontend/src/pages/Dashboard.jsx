// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import axios from 'axios';
import NetworkMap from '../components/NetworkMap.jsx';
import AlertsTable from '../components/AlertsTable.jsx';

const fetchDevices = async () => {
  const response = await axios.get('/api/v1/devices');
  return response.data;
};

export default function Dashboard() {
  const { data: devices = [] } = useQuery({
    queryKey: ['devices'],
    queryFn: fetchDevices,
    refetchInterval: 1000,
  });

  const metrics = useMemo(() => {
    if (!devices.length) {
      return {
        total: 0,
        blocked: 0,
        online: 0,
        traffic: 0,
      };
    }
    const traffic = devices.reduce((sum, device) => sum + (device.traffic_gb || 0), 0);
    return {
      total: devices.length,
      blocked: devices.filter((device) => device.status === 'blocked').length,
      online: devices.filter((device) => device.status === 'online').length,
      traffic,
    };
  }, [devices]);

  return (
    <div className="space-y-8 text-slate-100">
      <header className="space-y-2">
        <h1 className="text-3xl font-semibold tracking-tight">Operations Dashboard</h1>
        <p className="text-sm text-slate-400">Live network posture with real-time telemetry streaming from the EyeGuard sandbox.</p>
      </header>

      <section className="grid gap-6 xl:grid-cols-[2fr_1fr]">
        <div className="bg-[#0d172a] border border-slate-800/70 rounded-3xl p-6 shadow-[0_25px_60px_rgba(8,17,32,0.55)] space-y-6">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-xl font-semibold">Network Intelligence Grid</h2>
              <p className="text-xs uppercase tracking-[0.35em] text-slate-500">Device density vs. traffic throughput</p>
            </div>
            <span className="text-xs text-slate-500 font-mono">Auto-refresh 1s</span>
          </div>
          <NetworkMap devices={devices} />
        </div>

        <div className="flex flex-col gap-6">
          <div className="grid grid-cols-2 gap-4">
            <div className="bg-[#101b30] border border-slate-800/70 rounded-2xl p-4 shadow-inner shadow-slate-900/40">
              <p className="text-xs uppercase tracking-widest text-slate-500">Total Devices</p>
              <p className="text-3xl font-semibold text-slate-100 mt-2">{metrics.total}</p>
            </div>
            <div className="bg-[#101b30] border border-slate-800/70 rounded-2xl p-4 shadow-inner shadow-slate-900/40">
              <p className="text-xs uppercase tracking-widest text-slate-500">Online</p>
              <p className="text-3xl font-semibold text-emerald-300 mt-2">{metrics.online}</p>
            </div>
            <div className="bg-[#101b30] border border-slate-800/70 rounded-2xl p-4 shadow-inner shadow-slate-900/40">
              <p className="text-xs uppercase tracking-widest text-slate-500">Blocked</p>
              <p className="text-3xl font-semibold text-rose-300 mt-2">{metrics.blocked}</p>
            </div>
            <div className="bg-[#101b30] border border-slate-800/70 rounded-2xl p-4 shadow-inner shadow-slate-900/40">
              <p className="text-xs uppercase tracking-widest text-slate-500">Total Traffic</p>
              <p className="text-3xl font-semibold text-sky-300 mt-2">{metrics.traffic.toFixed(1)} GB</p>
            </div>
          </div>
          <div className="bg-[#101b30] border border-slate-800/70 rounded-3xl p-6 space-y-4 shadow-[0_18px_50px_rgba(7,15,30,0.45)]">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold">Device Feed</h3>
              <span className="text-xs text-slate-500">Sorted by recency</span>
            </div>
            <ul className="space-y-3">
              {devices.map((device) => {
                const trendingUp = (device.traffic_delta ?? 0) >= 0;
                const delta = Math.abs(device.traffic_delta ?? 0).toFixed(2);
                const deltaSign = trendingUp ? '+' : '-';
                const directionLabel = trendingUp ? 'UP' : 'DOWN';
                const color = trendingUp ? 'text-emerald-300' : 'text-amber-300';
                return (
                  <li key={device.id} className="flex items-center justify-between bg-slate-900/60 border border-slate-800/60 rounded-2xl px-4 py-3">
                    <div>
                      <p className="text-sm font-semibold text-slate-100">{device.hostname}</p>
                      <p className="text-xs text-slate-500 font-mono">{device.ip_address}</p>
                    </div>
                    <div className="text-right">
                      <p className="text-xs text-slate-500 uppercase">Traffic</p>
                      <p className={`text-sm font-semibold ${color}`}>
                        {device.traffic_gb.toFixed(2)} GB
                        <span className="ml-2 text-xs text-slate-400">{directionLabel} {deltaSign}{delta}</span>
                      </p>
                    </div>
                  </li>
                );
              })}
              {!devices.length && (
                <li className="text-sm text-slate-500">No devices registered yet.</li>
              )}
            </ul>
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
