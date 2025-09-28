import React, { createContext, useCallback, useEffect, useMemo, useState } from 'react';
import axios from 'axios';

const STORAGE_KEY = 'eyeguard-simulation-state';

const defaultContext = {
  session: null,
  history: [],
  alerts: [],
  statusMessage: null,
  startSession: () => {},
  updateSession: () => {},
  appendHistory: () => {},
  setAlerts: () => {},
  setStatusMessage: () => {},
  endSession: async () => {},
  clear: () => {},
};

export const SimulationContext = createContext(defaultContext);

const parseStorage = () => {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return { session: null, history: [], alerts: [], statusMessage: null };
    }
    const parsed = JSON.parse(raw);
    return {
      session: parsed.session ?? null,
      history: Array.isArray(parsed.history) ? parsed.history : [],
      alerts: Array.isArray(parsed.alerts) ? parsed.alerts : [],
      statusMessage: parsed.statusMessage ?? null,
    };
  } catch (error) {
    console.warn('Failed to parse simulation state from storage', error);
    return { session: null, history: [], alerts: [], statusMessage: null };
  }
};

const persistStorage = (state) => {
  try {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch (error) {
    console.warn('Failed to persist simulation state', error);
  }
};

export function SimulationProvider({ children }) {
  const initialState = useMemo(() => {
    if (typeof window === 'undefined') {
      return { session: null, history: [], alerts: [], statusMessage: null };
    }
    return parseStorage();
  }, []);

  const [session, setSession] = useState(initialState.session);
  const [history, setHistory] = useState(initialState.history);
  const [alerts, setAlertsState] = useState(initialState.alerts);
  const [statusMessage, setStatusMessage] = useState(initialState.statusMessage);

  useEffect(() => {
    persistStorage({ session, history, alerts, statusMessage });
  }, [session, history, alerts, statusMessage]);

  const clear = useCallback(() => {
    setSession(null);
    setHistory([]);
    setAlertsState([]);
    setStatusMessage(null);
  }, []);

  const startSession = useCallback((nextSession) => {
    setSession(nextSession);
    setHistory([]);
    setAlertsState([]);
    setStatusMessage(nextSession?.status_message ?? null);
  }, []);

  const updateSession = useCallback((partial) => {
    setSession((prev) => {
      if (!prev) {
        return prev;
      }
      const next = { ...prev, ...partial };
      if (partial && Object.prototype.hasOwnProperty.call(partial, 'status_message')) {
        setStatusMessage(partial.status_message ?? null);
      }
      return next;
    });
  }, []);

  const appendHistory = useCallback((entry) => {
    if (!entry) {
      return;
    }
    const entries = Array.isArray(entry) ? entry : [entry];
    setHistory((prev) => [...prev, ...entries]);
  }, []);

  const setAlerts = useCallback((nextAlerts) => {
    setAlertsState(Array.isArray(nextAlerts) ? nextAlerts : []);
  }, []);

  const endSession = useCallback(async () => {
    if (!session) {
      clear();
      return;
    }
    try {
      await axios.delete(`/api/v1/simulation/sessions/${session.session_id}`);
    } catch (error) {
      if (error?.response?.status !== 404) {
        console.warn('Failed to end simulation session', error);
      }
    } finally {
      clear();
    }
  }, [session, clear]);

  const value = useMemo(() => ({
    session,
    history,
    alerts,
    statusMessage,
    startSession,
    updateSession,
    appendHistory,
    setAlerts,
    setStatusMessage,
    endSession,
    clear,
  }), [session, history, alerts, statusMessage, startSession, updateSession, appendHistory, setAlerts, endSession, clear]);

  return (
    <SimulationContext.Provider value={value}>
      {children}
    </SimulationContext.Provider>
  );
}
