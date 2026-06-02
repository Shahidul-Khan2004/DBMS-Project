"use client";

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";

interface AgencyNavContextValue {
  menuOpen: boolean;
  openMenu: () => void;
  closeMenu: () => void;
}

const AgencyNavContext = createContext<AgencyNavContextValue | null>(null);

export function AgencyNavProvider({ children }: { children: ReactNode }) {
  const [menuOpen, setMenuOpen] = useState(false);

  const openMenu = useCallback(() => setMenuOpen(true), []);
  const closeMenu = useCallback(() => setMenuOpen(false), []);

  const value = useMemo(
    () => ({ menuOpen, openMenu, closeMenu }),
    [menuOpen, openMenu, closeMenu],
  );

  return (
    <AgencyNavContext.Provider value={value}>{children}</AgencyNavContext.Provider>
  );
}

export function useAgencyNav(): AgencyNavContextValue {
  const ctx = useContext(AgencyNavContext);
  if (!ctx) {
    throw new Error("useAgencyNav must be used within AgencyNavProvider");
  }
  return ctx;
}
