// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useMemo } from 'react';

export default function NetworkMap({ devices = [] }) {
  const maxTraffic = useMemo(() => {
    if (!devices.length) {
      return 1;
    }
    return Math.max(...devices.map((device) => device.traffic_gb || 0), 1);
  }, [devices]);

  return (
    <div className="relative h-80 rounded-3xl border border-slate-800/70 bg-gradient-to-br from-[#0f192d] via-[#0a1324] to-[#050912] overflow-hidden">
      <div className="absolute inset-0 pointer-events-none bg-[radial-gradient(circle_at_top,rgba(56,189,248,0.18),transparent_55%)]" />
      <div className="absolute left-[12%] right-[10%] bottom-[18%] h-px bg-slate-700/60" />
      <div className="absolute top-[12%] bottom-[18%] left-[12%] w-px bg-slate-700/60" />
      <div className="absolute top-[8%] left-[12%] text-xs uppercase tracking-[0.3em] text-slate-500">Traffic (GB)</div>
      <div className="absolute right-[10%] bottom-[12%] text-xs uppercase tracking-[0.3em] text-slate-500">Devices</div>

      {devices.map((device, index) => {
        const positionX = devices.length > 1 ? (index / (devices.length - 1)) * 70 + 12 : 50;
        const normalizedTraffic = Math.min((device.traffic_gb || 0) / maxTraffic, 1);
        const positionY = (1 - normalizedTraffic) * 60 + 18;
        const trendingUp = (device.traffic_delta ?? 0) >= 0;
        const nodeColor = trendingUp ? 'bg-emerald-400 shadow-[0_0_20px_rgba(34,197,94,0.45)]' : 'bg-amber-400 shadow-[0_0_20px_rgba(251,191,36,0.35)]';
        const deltaMagnitude = Math.abs(device.traffic_delta ?? 0).toFixed(2);
        const deltaSign = trendingUp ? '+' : '-';
        const directionLabel = trendingUp ? 'UP' : 'DOWN';
        return (
          <div key={device.id} className="absolute" style={{ left: `${positionX}%`, top: `${positionY}%` }}>
            <span className={`relative block h-3 w-3 rounded-full ${nodeColor}`}>
              <span className={`absolute inset-0 rounded-full ${trendingUp ? 'bg-emerald-400/60' : 'bg-amber-400/60'} animate-ping`} />
            </span>
            <div className="mt-2 flex flex-col gap-1 text-xs text-slate-400">
              <span className={`font-semibold ${trendingUp ? 'text-emerald-200' : 'text-amber-200'}`}>
                {device.traffic_gb.toFixed(2)} GB <span className="text-[10px]">{directionLabel} {deltaSign}{deltaMagnitude}</span>
              </span>
              <span className="font-mono text-[11px] text-slate-500">{device.ip_address}</span>
            </div>
          </div>
        );
      })}

      <div className="absolute left-[6%] bottom-[18%] flex flex-col gap-6 text-[10px] text-slate-500">
        {Array.from({ length: 5 }).map((_, index) => {
          const value = Math.round(((4 - index) / 4) * maxTraffic);
          return <span key={value}>{value} GB</span>;
        })}
      </div>

      <div className="absolute left-[12%] right-[10%] bottom-[8%] flex justify-between">
        {devices.map((device, index) => (
          <div key={device.id} className="flex flex-col items-center gap-2 w-full">
            <span className="text-[11px] text-slate-500">{index + 1}</span>
            <div className="h-10 w-10 rounded-2xl bg-slate-900/70 border border-slate-800/80 flex items-center justify-center text-xs text-sky-300 font-semibold shadow-inner shadow-slate-900/40">
              {device.hostname.slice(0, 2).toUpperCase()}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
