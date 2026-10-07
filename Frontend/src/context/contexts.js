import { createContext, useContext } from 'react';

export const ThemeContext = createContext({ theme: 'light', toggle: () => {} });
export const ToastContext = createContext({ toast: () => {} });
export const ConfirmContext = createContext({ confirm: async () => false });
export const AuthContext = createContext({ user: null, status: 'loading', signIn: () => {}, signOut: async () => {}, setUser: () => {} });

export const useTheme = () => useContext(ThemeContext);
export const useToast = () => useContext(ToastContext);
export const useConfirm = () => useContext(ConfirmContext);
export const useAuth = () => useContext(AuthContext);
