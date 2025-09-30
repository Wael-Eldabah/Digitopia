// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { useEffect, useMemo, useState } from 'react';
import { Navigate, Outlet, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import axios from 'axios';
import Sidebar from './components/Sidebar.jsx';
import AuthContext, { authContextDefaults } from './context/AuthContext.jsx';
import Dashboard from './pages/Dashboard.jsx';
import AlertsPage from './pages/AlertsPage.jsx';
import ReportsPage from './pages/ReportsPage.jsx';
import SimulationPage from './pages/SimulationPage.jsx';
import SettingsPage from './pages/SettingsPage.jsx';
import IPSearchPage from './pages/IPSearchPage.jsx';
import PcapAnalysisPage from './pages/PcapAnalysisPage.jsx';
import LoginPage from './pages/LoginPage.jsx';
import SignupPage from './pages/SignupPage.jsx';
import ForgotPasswordPage from './pages/ForgotPasswordPage.jsx';
import { SimulationProvider } from './context/SimulationContext.jsx';
import { AlertsIndicatorProvider } from './context/AlertsIndicatorContext.jsx';
import { hydrateUserProfile } from './utils/assets.js';


function ProtectedLayout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }
    const handleResize = () => {
      if (window.innerWidth >= 1024) {
        setSidebarOpen(false);
      }
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  useEffect(() => {
    if (!sidebarOpen) {
      return;
    }
    const handleKey = (event) => {
      if (event.key === 'Escape') {
        setSidebarOpen(false);
      }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [sidebarOpen]);

  return (
    <div className="flex min-h-screen bg-[#070d18] text-slate-100">
      <Sidebar
        collapsed={sidebarCollapsed}
        onCollapsedChange={setSidebarCollapsed}
        mobileOpen={sidebarOpen}
        onMobileClose={() => setSidebarOpen(false)}
      />
      <div className="flex flex-1 flex-col">
        <header className="flex items-center justify-between gap-3 border-b border-slate-800/60 bg-[#070d18]/95 px-4 py-3 backdrop-blur lg:hidden">
          <button
            type="button"
            onClick={() => setSidebarOpen(true)}
            className="inline-flex items-center justify-center rounded-xl border border-slate-700 p-2 text-slate-200 transition hover:bg-slate-800/60"
            aria-label="Open sidebar"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
              <path d="M4 6h16" />
              <path d="M4 12h16" />
              <path d="M4 18h16" />
            </svg>
          </button>
          <span className="text-sm font-semibold text-slate-200">EyeGuard Console</span>
          <span className="w-10" />
        </header>
        <main className="flex-1 overflow-x-hidden">
          <div className="mx-auto w-full max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}

function ProtectedRoute({ children }) {
  const { isAuthenticated } = React.useContext(AuthContext);
  const location = useLocation();

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return children;
}

export default function App() {
  const navigate = useNavigate();
  const [session, setSession] = useState(() => {
    try {
      const raw = localStorage.getItem('eyeguard-session');
      if (!raw) {
        return { token: null, user: null, managerPending: 0 };
      }
      const parsed = JSON.parse(raw);
      if (parsed?.token) {
        axios.defaults.headers.common['X-Eyeguard-Token'] = parsed.token;
      }
      return { token: parsed.token, user: hydrateUserProfile(parsed.user), managerPending: parsed.managerPending || 0 };
    } catch (error) {
      console.warn('Failed to restore session', error);
      return { token: null, user: null, managerPending: 0 };
    }
  });
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (session?.token) {
      axios.defaults.headers.common['X-Eyeguard-Token'] = session.token;
      localStorage.setItem('eyeguard-session', JSON.stringify(session));
    } else {
      delete axios.defaults.headers.common['X-Eyeguard-Token'];
      localStorage.removeItem('eyeguard-session');
    }
  }, [session]);

  const refreshProfile = async () => {
    if (!session?.token) {
      return;
    }
    try {
      const { data } = await axios.get('/api/v1/auth/me');
      const hydratedUser = hydrateUserProfile(data);
      setSession((prev) => ({ ...prev, user: hydratedUser }));
      if (hydratedUser?.role === 'MANAGER') {
        try {
          const count = await axios.get('/api/v1/settings/users/pending/count');
          setSession((prev) => ({ ...prev, managerPending: count.data?.pending ?? 0 }));
        } catch (error) {
          console.warn('Failed to fetch pending user count', error);
        }
      }
    } catch (error) {
      const status = error?.response?.status;
      console.warn('Failed to refresh profile', error);
      if (status === 401) {
        setSession({ token: null, user: null, managerPending: 0 });
      }
    }
  };

  useEffect(() => {
    if (session?.token) {
      refreshProfile();
    }
  }, [session?.token]);

  const login = async (credentials) => {
    setIsSubmitting(true);
    try {
      const { data } = await axios.post('/api/v1/auth/login', credentials);
      axios.defaults.headers.common['X-Eyeguard-Token'] = data.token;
      setSession({ token: data.token, user: hydrateUserProfile(data.user), managerPending: data.manager_pending_requests ?? 0 });
      return data;
    } finally {
      setIsSubmitting(false);
    }
  };

  const logout = () => {
    setSession({ token: null, user: null, managerPending: 0 });
    navigate('/login', { replace: true });
  };

  const updateUser = (nextUser) => {
    setSession((prev) => {
      if (!prev) {
        return prev;
      }
      return { ...prev, user: hydrateUserProfile(nextUser) };
    });
  };

  const setManagerPending = (count) => {
    setSession((prev) => ({ ...prev, managerPending: count }));
  };

  const authValue = useMemo(
    () => ({
      ...authContextDefaults,
      isAuthenticated: Boolean(session?.token),
      token: session?.token ?? null,
      user: session?.user ?? null,
      isSubmitting,
      managerPending: session?.managerPending ?? 0,
      login,
      logout,
      updateUser,
      setManagerPending,
      refreshProfile,
    }),
    [session, isSubmitting],
  );

  return (
    <AuthContext.Provider value={authValue}>
      <SimulationProvider>
        <AlertsIndicatorProvider>
          <Routes>
          <Route path="/login" element={<LoginPage isSubmitting={isSubmitting} onLogin={login} />} />
          <Route path="/signup" element={<SignupPage />} />
          <Route path="/forgot" element={<ForgotPasswordPage />} />
          <Route
            path="/"
            element={(
              <ProtectedRoute>
                <ProtectedLayout />
              </ProtectedRoute>
            )}
          >
            <Route index element={<Dashboard />} />
            <Route path="alerts" element={<AlertsPage />} />
            <Route path="reports" element={<ReportsPage />} />
            <Route path="simulation" element={<SimulationPage />} />
            <Route path="pcap" element={<PcapAnalysisPage />} />
            <Route path="settings" element={<SettingsPage />} />
            <Route path="search" element={<IPSearchPage />} />
          </Route>
          <Route path="*" element={<Navigate to={session?.token ? '/' : '/login'} replace />} />
          </Routes>
        </AlertsIndicatorProvider>
      </SimulationProvider>
    </AuthContext.Provider>
  );
}
