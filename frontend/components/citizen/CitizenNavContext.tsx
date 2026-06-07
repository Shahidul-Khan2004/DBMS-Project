"use client";

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";

interface CitizenNavContextValue {
  menuOpen: boolean;
  openMenu: () => void;
  closeMenu: () => void;
}

const CitizenNavContext = createContext<CitizenNavContextValue | null>(null);

export function CitizenNavProvider({ children }: { children: ReactNode }) {
  const [menuOpen, setMenuOpen] = useState(false);

  const openMenu = useCallback(() => setMenuOpen(true), []);
  const closeMenu = useCallback(() => setMenuOpen(false), []);

  const value = useMemo(
    () => ({ menuOpen, openMenu, closeMenu }),
    [menuOpen, openMenu, closeMenu],
  );

  return (
    <CitizenNavContext.Provider value={value}>
      {children}
    </CitizenNavContext.Provider>
  );
}

export function useCitizenNav(): CitizenNavContextValue {
  const ctx = useContext(CitizenNavContext);
  if (!ctx) {
    throw new Error("useCitizenNav must be used within CitizenNavProvider");
  }
  return ctx;
}
