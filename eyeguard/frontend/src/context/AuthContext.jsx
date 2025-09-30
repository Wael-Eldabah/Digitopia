// Software-only simulation / demo - no real systems will be contacted or modified.
import { createContext } from 'react';

export const authContextDefaults = {
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
};

const AuthContext = createContext(authContextDefaults);

export default AuthContext;
