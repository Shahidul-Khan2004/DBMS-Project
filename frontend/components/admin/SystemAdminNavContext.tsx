"use client";

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";

interface SystemAdminNavContextValue {
  menuOpen: boolean;
  openMenu: () => void;
  closeMenu: () => void;
}

const SystemAdminNavContext = createContext<SystemAdminNavContextValue | null>(
  null,
);

export function SystemAdminNavProvider({ children }: { children: ReactNode }) {
  const [menuOpen, setMenuOpen] = useState(false);

  const openMenu = useCallback(() => setMenuOpen(true), []);
  const closeMenu = useCallback(() => setMenuOpen(false), []);

  const value = useMemo(
    () => ({ menuOpen, openMenu, closeMenu }),
    [menuOpen, openMenu, closeMenu],
  );

  return (
    <SystemAdminNavContext.Provider value={value}>
      {children}
    </SystemAdminNavContext.Provider>
  );
}

export function useSystemAdminNav(): SystemAdminNavContextValue {
  const ctx = useContext(SystemAdminNavContext);
  if (!ctx) {
    throw new Error(
      "useSystemAdminNav must be used within SystemAdminNavProvider",
    );
  }
  return ctx;
}
