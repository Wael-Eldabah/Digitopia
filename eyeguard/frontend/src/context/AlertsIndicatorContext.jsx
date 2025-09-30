// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { createContext, useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import axios from 'axios';

const ACTIVE_STATUSES = new Set(['Open', 'Acknowledged']);
const LAST_SEEN_KEY = 'eyeguard:last-alert-seen';

const fetchAlertsSnapshot = async () => {
  const { data } = await axios.get('/api/v1/alerts');
  if (Array.isArray(data)) {
    return data;
  }
  if (Array.isArray(data?.items)) {
    return data.items;
  }
  return [];
};

const toTimestamp = (value) => {
  if (!value) {
    return 0;
  }
  const time = new Date(value).getTime();
  return Number.isFinite(time) ? time : 0;
};

const readLastSeen = () => {
  if (typeof window === 'undefined') {
    return 0;
  }
  const raw = window.localStorage.getItem(LAST_SEEN_KEY);
  const parsed = raw ? Number(raw) : 0;
  return Number.isFinite(parsed) ? parsed : 0;
};

const persistLastSeen = (timestamp) => {
  if (typeof window === 'undefined') {
    return;
  }
  window.localStorage.setItem(LAST_SEEN_KEY, String(timestamp));
};

export const AlertsIndicatorContext = createContext({
  isLoading: false,
  totalAlerts: 0,
  activeAlerts: 0,
  unseenAlerts: 0,
  latestAlert: null,
  markAlertsSeen: () => {},
  refetch: () => {},
});

export function AlertsIndicatorProvider({ children }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [banner, setBanner] = useState(null);
  const [unseenAlerts, setUnseenAlerts] = useState(0);
  const latestSeenIdRef = useRef(null);
  const lastSeenTimestampRef = useRef(readLastSeen());
  const initializedRef = useRef(false);

  const query = useQuery({
    queryKey: ['alerts-indicator'],
    queryFn: fetchAlertsSnapshot,
    refetchInterval: 5000,
    staleTime: 4000,
  });

  const alerts = Array.isArray(query.data) ? query.data : [];
  const activeAlerts = useMemo(
    () => alerts.filter((entry) => ACTIVE_STATUSES.has((entry.status || '').trim())).length,
    [alerts],
  );
  const latestAlert = alerts[0] || null;

  useEffect(() => {
    if (!alerts.length) {
      setUnseenAlerts(0);
      return;
    }
    const unseen = alerts.filter((entry) => toTimestamp(entry.detected_at) > lastSeenTimestampRef.current).length;
    setUnseenAlerts(unseen);
  }, [alerts]);

  useEffect(() => {
    if (!latestAlert || !latestAlert.id) {
      return;
    }
    const latestId = latestAlert.id;
    if (!initializedRef.current) {
      initializedRef.current = true;
      latestSeenIdRef.current = latestId;
      if (lastSeenTimestampRef.current === 0) {
        lastSeenTimestampRef.current = toTimestamp(latestAlert.detected_at);
      }
      return;
    }
    const isNewAlert = latestSeenIdRef.current !== latestId;
    if (isNewAlert) {
      latestSeenIdRef.current = latestId;
      setBanner({
        id: latestId,
        category: latestAlert.category,
        severity: latestAlert.severity,
        detected_at: latestAlert.detected_at,
      });
    }
  }, [latestAlert]);

  useEffect(() => {
    if (!banner) {
      return undefined;
    }
    const timer = typeof window !== 'undefined'
      ? window.setTimeout(() => {
          setBanner(null);
        }, 12000)
      : null;

    return () => {
      if (typeof window !== 'undefined' && timer) {
        window.clearTimeout(timer);
      }
    };
  }, [banner]);

  const markAlertsSeen = (timestamp = Date.now()) => {
    lastSeenTimestampRef.current = timestamp;
    persistLastSeen(timestamp);
    setUnseenAlerts(0);
  };

  useEffect(() => {
    if (location.pathname === '/alerts' && alerts.length) {
      const newestTimestamp = toTimestamp(alerts[0]?.detected_at);
      markAlertsSeen(newestTimestamp);
      setBanner(null);
    }
  }, [location.pathname, alerts]);

  const dismissBanner = () => setBanner(null);
  const viewAlerts = () => {
    setBanner(null);
    markAlertsSeen(alerts.length ? toTimestamp(alerts[0]?.detected_at) : Date.now());
    navigate('/alerts');
  };

  const value = useMemo(
    () => ({
      isLoading: query.isLoading,
      totalAlerts: alerts.length,
      activeAlerts,
      unseenAlerts,
      latestAlert,
      markAlertsSeen,
      refetch: query.refetch,
    }),
    [query.isLoading, query.refetch, alerts.length, activeAlerts, unseenAlerts, latestAlert],
  );

  return (
    <AlertsIndicatorContext.Provider value={value}>
      {children}
      <AlertNotification banner={banner} onDismiss={dismissBanner} onView={viewAlerts} />
    </AlertsIndicatorContext.Provider>
  );
}

function AlertNotification({ banner, onDismiss, onView }) {
  if (!banner) {
    return null;
  }

  const severity = (banner.severity || '').toUpperCase();
  const severityClass = severity === 'HIGH'
    ? 'text-rose-200 bg-rose-500/10 border border-rose-500/40'
    : severity === 'MEDIUM'
      ? 'text-amber-200 bg-amber-500/10 border border-amber-500/40'
      : 'text-sky-200 bg-sky-500/10 border border-sky-500/40';

  const formatTimestamp = (value) => {
    if (!value) {
      return 'Just now';
    }
    try {
      return new Date(value).toLocaleString();
    } catch (error) {
      return String(value);
    }
  };

  return (
    <div className="fixed inset-x-0 top-4 z-[60] flex justify-center px-4">
      <div className="w-full max-w-lg rounded-2xl border border-slate-800 bg-[#10192c] shadow-2xl shadow-slate-900/50">
        <div className="flex items-start gap-4 p-4">
          <div className={`mt-1 inline-flex rounded-lg px-2 py-1 text-[11px] font-semibold ${severityClass}`}>
            {severity || 'INFO'}
          </div>
          <div className="flex-1 space-y-1">
            <p className="text-sm font-semibold text-slate-100">New alert detected</p>
            <p className="text-sm text-slate-300">{banner.category || 'Alert'} • {formatTimestamp(banner.detected_at)}</p>
            <div className="flex flex-wrap gap-2 pt-2">
              <button
                type="button"
                onClick={onView}
                className="rounded-lg border border-sky-500 px-3 py-1.5 text-xs font-semibold text-sky-200 transition hover:bg-sky-500/10"
              >
                View alerts
              </button>
              <button
                type="button"
                onClick={onDismiss}
                className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs font-semibold text-slate-300 transition hover:bg-slate-800/60"
              >
                Dismiss
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
