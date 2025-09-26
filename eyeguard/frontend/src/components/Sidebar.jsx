// Software-only simulation / demo - no real systems will be contacted or modified.
import React from 'react';
import { NavLink } from 'react-router-dom';
import { AuthContext } from '../App.jsx';

const navItems = [
  { label: 'Dashboard', path: '/', icon: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M3 9.5 12 4l9 5.5" />
      <path d="M19 10v8a1 1 0 0 1-1 1h-3v-5h-6v5H6a1 1 0 0 1-1-1v-8" />
    </svg>
  ) },
  { label: 'Alerts & Incidents', path: '/alerts', icon: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M4 19h16" />
      <path d="M9 19V9a3 3 0 0 1 6 0v10" />
      <path d="M12 2v2" />
    </svg>
  ) },
  { label: 'Reports', path: '/reports', icon: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M6 4h9l3 3v13H6z" />
      <path d="M14 4v4h4" />
    </svg>
  ) },
  { label: 'Simulation', path: '/simulation', icon: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <rect x="3" y="4" width="7" height="7" rx="1" />
      <rect x="14" y="4" width="7" height="7" rx="1" />
      <rect x="3" y="15" width="7" height="7" rx="1" />
      <path d="M14 15h7v7h-7z" />
    </svg>
  ) },
  { label: 'IP Search', path: '/search', icon: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <circle cx="11" cy="11" r="7" />
      <path d="m20 20-3.5-3.5" />
    </svg>
  ) },
  { label: 'Settings', path: '/settings', icon: (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6">
      <path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z" />
      <path d="m19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9c0 .69.4 1.31 1.02 1.59.18.08.37.12.58.12H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z" />
    </svg>
  ) },
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

export default function Sidebar() {
  const { user, logout, managerPending } = React.useContext(AuthContext);
  const displayName = user?.display_name || user?.email || 'Analyst';
  const initials = initialsFromName(displayName, 'EG');
  const roleLabel = user?.role ? user.role.replace('_', ' ') : 'Guest';
  const avatarStyle = { backgroundImage: colorFromSeed(user?.avatar_seed || 'eyeguard') };

  return (
    <aside className="w-72 min-h-screen bg-[#0b1323] border-r border-slate-800/60 text-slate-300 flex flex-col">
      <div className="px-6 pt-8 pb-6 border-b border-slate-800/60">
        <div className="flex items-center gap-3">
          <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-sky-500 via-blue-500 to-indigo-500 flex items-center justify-center shadow-lg shadow-sky-500/25">
            <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4" className="text-slate-950">
              <path d="M12 2 3 6v6c0 5 3.8 9.7 9 10 5.2-.3 9-5 9-10V6l-9-4Z" fill="currentColor" opacity="0.15" />
              <path d="m12 22 9-6V6l-9 4m0 12-9-6V6l9 4" />
              <path d="M12 10v12" />
            </svg>
          </div>
          <div>
            <p className="text-lg font-semibold text-slate-100">EyeGuard</p>
            <p className="text-xs text-slate-500">SOC Simulation Console</p>
          </div>
        </div>
      </div>
      <nav className="flex-1 px-5 py-6 space-y-1">
        {navItems.map((item) => {
          const isSettings = item.path === '/settings';
          const showBadge = isSettings && user?.role === 'MANAGER' && managerPending > 0;
          return (
            <NavLink
              key={item.path}
              to={item.path}
              end={item.path === '/'}
              className={({ isActive }) =>
                `flex items-center justify-between gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-gradient-to-r from-sky-600/30 via-emerald-500/20 to-transparent border border-sky-500/40 text-slate-100'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/40'
                }`
              }
            >
              <span className="flex items-center gap-3">
                <span className="text-sky-300/80">{item.icon}</span>
                <span>{item.label}</span>
              </span>
              {showBadge && (
                <span className="text-[11px] font-semibold text-slate-900 bg-emerald-400/90 px-2 py-0.5 rounded-full">
                  {managerPending}
                </span>
              )}
            </NavLink>
          );
        })}
      </nav>
      <div className="px-6 pb-8 pt-6 border-t border-slate-800/60">
        <div className="flex items-center gap-3">
          {user?.profile_image_url ? (
            <img
              src={user.profile_image_url}
              alt={displayName}
              className="w-11 h-11 rounded-full object-cover border border-slate-700"
            />
          ) : (
            <div className="w-11 h-11 rounded-full flex items-center justify-center text-sm font-semibold text-slate-950" style={avatarStyle}>
              {initials}
            </div>
          )}
          <div className="flex-1">
            <p className="text-sm font-semibold text-slate-100">{displayName}</p>
            <p className="text-xs text-slate-500 uppercase">{roleLabel}</p>
          </div>
        </div>
        <button
          type="button"
          onClick={logout}
          className="mt-4 w-full py-2.5 rounded-xl border border-slate-700 text-sm font-medium text-slate-300 hover:bg-slate-800/60 transition"
        >
          Logout
        </button>
      </div>
    </aside>
  );
}
