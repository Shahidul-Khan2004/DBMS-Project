"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect } from "react";
import { X } from "lucide-react";
import { useSystemAdminNav } from "@/components/admin/SystemAdminNavContext";
import {
  ADMIN_OPS_TABS,
  isAdminOpsTabActive,
  isNationalDisasterRoute,
} from "@/components/admin/adminOpsSection";
import { DISPATCHER_EMERGENCY_ACTIVE_RING_CLASSES } from "@/components/dispatcher/emergencyColors";
import { nationalDisasterLandingPath } from "@/lib/admin-national-disaster-routes";

const linkClass = (active: boolean) =>
  `flex items-center justify-between rounded-lg px-3 py-2.5 text-sm font-medium transition-colors ${
    active
      ? "bg-[#002D62] text-white shadow-sm"
      : "text-slate-700 hover:bg-[#EFF6FF] hover:text-[#006747]"
  }`;

const nationalDisasterLinkClass = (active: boolean) =>
  `flex w-full items-center justify-between rounded-lg border border-[#991B1B] px-3 py-2.5 text-sm font-medium shadow-sm transition-colors ${
    active
      ? `bg-[#B91C1C] text-white ${DISPATCHER_EMERGENCY_ACTIVE_RING_CLASSES}`
      : "bg-[#B91C1C] text-white hover:bg-[#991B1B]"
  }`;

export function SystemAdminDrawer() {
  const pathname = usePathname();
  const { menuOpen, closeMenu } = useSystemAdminNav();
  const isNationalDisasterActive = isNationalDisasterRoute(pathname);

  useEffect(() => {
    if (!menuOpen) return;

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        closeMenu();
      }
    };

    window.addEventListener("keydown", onKeyDown);

    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [menuOpen, closeMenu]);

  if (!menuOpen) return null;

  return (
    <div className="fixed inset-0 z-50 xl:hidden" role="presentation">
      <button
        type="button"
        className="absolute inset-0 bg-black/40"
        aria-label="Close admin navigation"
        onClick={closeMenu}
      />
      <aside
        role="dialog"
        aria-modal="true"
        aria-label="System admin navigation"
        className="absolute inset-y-0 right-0 flex w-full max-w-sm flex-col border-l border-[#002D62]/10 bg-white shadow-2xl shadow-[#002D62]/15"
      >
        <div className="flex items-center justify-between border-b border-[#002D62]/10 px-4 py-4">
          <span className="text-sm font-semibold text-[#002D62]">
            System Admin
          </span>
          <button
            type="button"
            onClick={closeMenu}
            className="inline-flex h-9 w-9 items-center justify-center rounded-lg border-2 border-[#002D62] bg-white text-[#002D62] transition-colors hover:bg-[#EFF6FF]"
            aria-label="Close admin navigation"
          >
            <X className="h-5 w-5" aria-hidden />
          </button>
        </div>

        <nav
          className="flex flex-1 flex-col overflow-y-auto px-4 py-4"
          aria-label="System admin"
        >
          <ul className="space-y-1">
            {ADMIN_OPS_TABS.map((tab) => {
              const active = isAdminOpsTabActive(pathname, tab.href);
              return (
                <li key={tab.href}>
                  <Link
                    href={tab.href}
                    className={linkClass(active)}
                    onClick={closeMenu}
                  >
                    <span>{tab.label}</span>
                    {active ? (
                      <span className="text-xs font-semibold uppercase tracking-wide">
                        Active
                      </span>
                    ) : null}
                  </Link>
                </li>
              );
            })}
          </ul>

          <div className="mt-6 border-t border-[#002D62]/10 pt-6">
            <Link
              href={nationalDisasterLandingPath()}
              className={nationalDisasterLinkClass(isNationalDisasterActive)}
              onClick={closeMenu}
              aria-current={isNationalDisasterActive ? "page" : undefined}
            >
              <span>National Disaster</span>
              {isNationalDisasterActive ? (
                <span className="text-xs font-semibold uppercase tracking-wide">
                  Active
                </span>
              ) : null}
            </Link>
          </div>
        </nav>
      </aside>
    </div>
  );
}
