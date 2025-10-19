// Software-only simulation / demo - no real systems will be contacted or modified.
import React from 'react';
import PropTypes from 'prop-types';
import { NavLink } from 'react-router-dom';
import AuthContext from '../context/AuthContext.jsx';
import { AlertsIndicatorContext } from '../context/AlertsIndicatorContext.jsx';
import { resolveAssetUrl } from '../utils/assets.js';

const navItems = [
  {
    label: 'Dashboard',
    path: '/',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
        <path d="M3 9.5 12 4l9 5.5" />
        <path d="M19 10v8a1 1 0 0 1-1 1h-3v-5h-6v5H6a1 1 0 0 1-1-1v-8" />
      </svg>
    ),
  },
  {
    label: 'Alerts & Incidents',
    path: '/alerts',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
        <path d="M4 19h16" />
        <path d="M9 19V9a3 3 0 0 1 6 0v10" />
        <path d="M12 2v2" />
      </svg>
    ),
  },
  {
    label: 'Reports',
    path: '/reports',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
        <path d="M6 4h9l3 3v13H6z" />
        <path d="M14 4v4h4" />
      </svg>
    ),
  },
  {
    label: 'Threat Forecast',
    path: '/forecast',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
        <path d="M3 3v18" />
        <path d="M3 17h4l3-7 4 5 3-3 4 4" />
        <circle cx="18" cy="7" r="1.6" />
      </svg>
    ),
  },
  {
    label: 'Phishing Analysis',
    path: '/phishing',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
        <path d="M12 22c4 0 7-3 7-7V5" />
        <path d="m17 9-5 5-5-5" />
        <path d="M12 4v10" />
        <circle cx="12" cy="4" r="2" />
      </svg>
    ),
  },
  {
    label: 'MITRE ATT&CK',
    path: '/mitre',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
        <path d="M4 6h6l2 3h8" />
        <circle cx="4" cy="6" r="1.4" />
        <circle cx="10" cy="6" r="1.4" />
        <circle cx="12" cy="9" r="1.4" />
        <circle cx="20" cy="9" r="1.4" />
        <path d="M12 9v5l-2 4H6" />
        <circle cx="12" cy="14" r="1.4" />
        <circle cx="10" cy="18" r="1.4" />
        <circle cx="6" cy="18" r="1.4" />
      </svg>
    ),
  },
  {
    label: 'Simulation',
    path: '/simulation',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
        <rect x="3" y="4" width="7" height="7" rx="1" />
        <rect x="14" y="4" width="7" height="7" rx="1" />
        <rect x="3" y="15" width="7" height="7" rx="1" />
        <path d="M14 15h7v7h-7z" />
      </svg>
    ),
  },
  {
    label: 'PCAP Analyzer',
    path: '/pcap',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
        <path d="M4 16v-4a8 8 0 1 1 16 0v4" />
        <path d="M7 20h10" />
        <path d="M12 12v8" />
      </svg>
    ),
  },
  {
    label: 'IP & URL Search',
    path: '/search',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
        <circle cx="11" cy="11" r="7" />
        <path d="m20 20-3.5-3.5" />
      </svg>
    ),
  },
  {
    label: 'Settings',
    path: '/settings',
    icon: (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
        <path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z" />
        <path d="m19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9c0 .69.4 1.31 1.02 1.59.18.08.37.12.58.12H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z" />
      </svg>
    ),
  },
];

const initialsFromName = (name, fallback) => {
  if (!name) {
    return fallback;
  }
  const parts = name.trim().split(/\s+/);
  const letters = parts.slice(0, 2).map((chunk) => chunk[0]?.toUpperCase() || '').join('');
  return letters || fallback;
};

const colorFromSeed = (seed = 'eyeguard') => {
  let hash = 0;
  for (let i = 0; i < seed.length; i += 1) {
    hash = seed.charCodeAt(i) + ((hash << 5) - hash);
  }
  const hue = Math.abs(hash) % 360;
  return `linear-gradient(135deg, hsl(${hue} 70% 55%), hsl(${(hue + 60) % 360} 65% 45%))`;
};

export default function Sidebar({ collapsed = false, onCollapsedChange, mobileOpen = false, onMobileClose }) {
  const { user, logout, managerPending } = React.useContext(AuthContext);
  const { unseenAlerts } = React.useContext(AlertsIndicatorContext);
  const displayName = user?.display_name || user?.email || 'Analyst';
  const initials = initialsFromName(displayName, 'EG');
  const roleLabel = user?.role ? user.role.replace('_', ' ') : 'Guest';
  const avatarUrl = resolveAssetUrl(user?.profile_image_url);
  const avatarStyle = { backgroundImage: colorFromSeed(user?.avatar_seed || 'eyeguard') };
  const [isDesktop, setIsDesktop] = React.useState(() => {
    if (typeof window === 'undefined') {
      return false;
    }
    return window.matchMedia('(min-width: 1024px)').matches;
  });

  React.useEffect(() => {
    if (typeof window === 'undefined') {
      return undefined;
    }
    const mediaQuery = window.matchMedia('(min-width: 1024px)');
    const handleChange = (event) => setIsDesktop(event.matches);
    setIsDesktop(mediaQuery.matches);
    if (typeof mediaQuery.addEventListener === 'function') {
      mediaQuery.addEventListener('change', handleChange);
      return () => mediaQuery.removeEventListener('change', handleChange);
    }
    mediaQuery.addListener(handleChange);
    return () => mediaQuery.removeListener(handleChange);
  }, []);

  const handleCollapseToggle = () => {
    if (typeof onCollapsedChange === 'function') {
      onCollapsedChange(!collapsed);
    }
  };

  const handleMobileClose = () => {
    if (typeof onMobileClose === 'function') {
      onMobileClose();
    }
  };

  const containerClasses = [
    'fixed inset-y-0 left-0 z-50 flex min-h-screen flex-col border-r border-slate-800/60 bg-[#0b1323] text-slate-300 transition-all duration-300 ease-in-out',
    mobileOpen ? 'translate-x-0' : '-translate-x-full',
    'w-72',
    'lg:static lg:translate-x-0',
    collapsed ? 'lg:w-20' : 'lg:w-72',
  ].join(' ');

  const navLinkBase = collapsed
    ? 'group relative flex items-center justify-center gap-0 rounded-xl px-3 py-3 text-sm font-medium transition-all'
    : 'group relative flex items-center justify-between gap-3 rounded-xl px-4 py-3 text-sm font-medium transition-all';
  const showBadges = isDesktop || mobileOpen;

  return (
    <>
      {mobileOpen && (
        <button
          type="button"
          aria-label="Close sidebar"
          onClick={handleMobileClose}
          className="fixed inset-0 z-40 bg-slate-950/60 backdrop-blur-sm lg:hidden"
        />
      )}
      <aside className={containerClasses}>
        <div className={`border-b border-slate-800/60 px-6 pt-8 pb-6 transition-all ${collapsed ? 'lg:px-4' : ''}`}>
          <div className="flex items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-gradient-to-br from-sky-500 via-blue-500 to-indigo-500 shadow-lg shadow-sky-500/25">
                <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4" className="text-slate-950">
                  <path d="M12 2 3 6v6c0 5 3.8 9.7 9 10 5.2-.3 9-5 9-10V6l-9-4Z" fill="currentColor" opacity="0.15" />
                  <path d="m12 22 9-6V6l-9 4m0 12-9-6V6l9 4" />
                  <path d="M12 10v12" />
                </svg>
              </div>
              <div className={`${collapsed ? 'hidden lg:block lg:w-0 lg:overflow-hidden lg:opacity-0' : ''}`}>
                <p className="text-lg font-semibold text-slate-100">EyeGuard</p>
                <p className="text-xs text-slate-500">SOC Simulation Console</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
                onClick={handleCollapseToggle}
                className="hidden rounded-xl border border-slate-700 p-2 text-slate-300 transition hover:bg-slate-800/60 lg:inline-flex"
              >
                {collapsed ? (
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                    <path d="m9 6 6 6-6 6" />
                  </svg>
                ) : (
                  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                    <path d="m15 6-6 6 6 6" />
                  </svg>
                )}
              </button>
              <button
                type="button"
                aria-label="Close sidebar"
                onClick={handleMobileClose}
                className="inline-flex rounded-xl border border-slate-700 p-2 text-slate-300 transition hover:bg-slate-800/60 lg:hidden"
              >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                  <path d="M6 6 18 18" />
                  <path d="M6 18 18 6" />
                </svg>
              </button>
            </div>
          </div>
        </div>
        <nav className={`flex-1 space-y-1 px-5 py-6 transition-all ${collapsed ? 'lg:px-3' : ''}`}>
          {navItems.map((item) => {
            const isSettings = item.path === '/settings';
            const isAlerts = item.path === '/alerts';
            const showSettingsBadge = isSettings && user?.role === 'MANAGER' && managerPending > 0;
            const showAlertsBadge = isAlerts && unseenAlerts > 0;
            const badgeClass = collapsed
              ? 'hidden lg:flex lg:absolute lg:-right-1 lg:top-2 lg:h-5 lg:w-5 lg:items-center lg:justify-center lg:rounded-full lg:text-[10px] font-semibold text-slate-900'
              : 'rounded-full px-2 py-0.5 text-[11px] font-semibold text-slate-900';
            return (
              <NavLink
                key={item.path}
                to={item.path}
                end={item.path === '/'}
                onClick={() => {
                  if (mobileOpen) {
                    handleMobileClose();
                  }
                }}
                title={item.label}
                className={({ isActive }) =>
                  `${navLinkBase} ${
                    isActive
                      ? 'border border-sky-500/40 bg-gradient-to-r from-sky-600/30 via-emerald-500/20 to-transparent text-slate-100'
                      : 'text-slate-400 hover:bg-slate-800/40 hover:text-slate-100'
                  }`
                }
              >
                <span className={`flex items-center gap-3 ${collapsed ? 'lg:flex-col lg:gap-1' : ''}`}>
                <span className="text-sky-300/80">{item.icon}</span>
                <span className={`${collapsed ? 'lg:hidden' : ''}`}>{item.label}</span>
              </span>
              {showBadges && showSettingsBadge && (
                <span className={`${badgeClass} bg-emerald-400/90`}>
                  {managerPending}
                </span>
              )}
              {showBadges && showAlertsBadge && (
                <span className={`${badgeClass} bg-rose-400/90`}>
                  {unseenAlerts}
                </span>
              )}
            </NavLink>
            );
          })}
        </nav>
        <div className={`border-t border-slate-800/60 px-6 pb-8 pt-6 transition-all ${collapsed ? 'lg:px-4' : ''}`}>
          <div className={`flex items-center gap-3 ${collapsed ? 'lg:flex-col lg:items-center lg:gap-2' : ''}`}>
            {avatarUrl ? (
              <img src={avatarUrl} alt={displayName} className="h-11 w-11 rounded-full border border-slate-700 object-cover" />
            ) : (
              <div
                className="flex h-11 w-11 items-center justify-center rounded-full text-sm font-semibold text-slate-950"
                style={avatarStyle}
              >
                {initials}
              </div>
            )}
            <div className={`${collapsed ? 'hidden lg:block lg:text-center' : 'flex-1'}`}>
              <p className="text-sm font-semibold text-slate-100">{displayName}</p>
              <p className="text-xs uppercase text-slate-500">{roleLabel}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={logout}
            className="mt-4 w-full rounded-xl border border-slate-700 py-2.5 text-sm font-medium text-slate-300 transition hover:bg-slate-800/60"
            title="Logout"
          >
            <span className={`${collapsed ? 'hidden lg:inline' : 'hidden'}`}>
              <svg
                width="18"
                height="18"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.8"
                className="mx-auto"
              >
                <path d="M10 17 15 12 10 7" />
                <path d="M15 12H3" />
                <path d="M21 3v18" />
              </svg>
            </span>
            <span className={`${collapsed ? 'lg:hidden' : ''}`}>Logout</span>
          </button>
        </div>
      </aside>
    </>
  );
}

Sidebar.propTypes = {
  collapsed: PropTypes.bool,
  onCollapsedChange: PropTypes.func,
  mobileOpen: PropTypes.bool,
  onMobileClose: PropTypes.func,
};
