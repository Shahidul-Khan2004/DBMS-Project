"use client";

import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useState,
  type ReactNode,
} from "react";

interface DispatcherNavContextValue {
  menuOpen: boolean;
  openMenu: () => void;
  closeMenu: () => void;
}

const DispatcherNavContext = createContext<DispatcherNavContextValue | null>(
  null,
);

export function DispatcherNavProvider({ children }: { children: ReactNode }) {
  const [menuOpen, setMenuOpen] = useState(false);

  const openMenu = useCallback(() => setMenuOpen(true), []);
  const closeMenu = useCallback(() => setMenuOpen(false), []);

  const value = useMemo(
    () => ({ menuOpen, openMenu, closeMenu }),
    [menuOpen, openMenu, closeMenu],
  );

  return (
    <DispatcherNavContext.Provider value={value}>
      {children}
    </DispatcherNavContext.Provider>
  );
}

export function useDispatcherNav(): DispatcherNavContextValue {
  const ctx = useContext(DispatcherNavContext);
  if (!ctx) {
    throw new Error("useDispatcherNav must be used within DispatcherNavProvider");
  }
  return ctx;
}
