// Software-only simulation / demo - no real systems will be contacted or modified.
import React, { createContext, useEffect, useMemo, useState } from 'react';
import { Navigate, Outlet, Route, Routes, useLocation, useNavigate } from 'react-router-dom';
import axios from 'axios';
import Sidebar from './components/Sidebar.jsx';
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
import { hydrateUserProfile } from './utils/assets.js';

export const AuthContext = createContext({
  isAuthenticated: false,
  token: null,
  user: null,
  isSubmitting: false,
  managerPending: 0,
  login: async () => {},
  logout: () => {},
  updateUser: () => {},
  setManagerPending: () => {},
  refreshProfile: async () => {},
});

function ProtectedLayout() {
  return (
    <div className="flex">
      <Sidebar />
      <main className="flex-1 min-h-screen bg-[#070d18] text-slate-100">
        <div className="p-8">
          <Outlet />
        </div>
      </main>
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
          // ignore count fetch issues in simulation
        }
      }
    } catch (error) {
      console.warn('Failed to refresh profile', error);
      setSession({ token: null, user: null, managerPending: 0 });
    }
  };

  useEffect(() => {
    if (session?.token && !session?.user) {
      refreshProfile();
    }
  }, [session?.token]);

  const login = async (credentials) => {
    setIsSubmitting(true);
    try {
      const { data } = await axios.post('/api/v1/auth/login', credentials);
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
      </SimulationProvider>
    </AuthContext.Provider>
  );
}
