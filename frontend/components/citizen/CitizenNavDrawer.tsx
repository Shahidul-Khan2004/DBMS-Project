"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect } from "react";
import { Plus, X } from "lucide-react";
import { useCitizenNav } from "@/components/citizen/CitizenNavContext";
import {
  CITIZEN_NAV_ITEMS,
  isCitizenNavItemActive,
} from "@/components/citizen/citizenNavSection";

const linkClass = (active: boolean) =>
  `flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors ${
    active
      ? "bg-[#EFF6FF] text-[#0B3FE8]"
      : "text-[#1F3768] hover:bg-[#F6F9FE] hover:text-[#0B3FE8]"
  }`;

export function CitizenNavDrawer({
  showReportAction,
}: {
  showReportAction: boolean;
}) {
  const pathname = usePathname();
  const { menuOpen, closeMenu } = useCitizenNav();

  useEffect(() => {
    closeMenu();
  }, [pathname, closeMenu]);

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
    <div className="fixed inset-0 z-50 lg:hidden" role="presentation">
      <button
        type="button"
        className="absolute inset-0 bg-black/40"
        aria-label="Close citizen navigation"
        onClick={closeMenu}
      />
      <aside
        role="dialog"
        aria-modal="true"
        aria-label="Citizen navigation"
        className="absolute inset-y-0 right-0 flex w-full max-w-sm flex-col border-l border-[#002D62]/10 bg-white shadow-2xl shadow-[#002D62]/15"
      >
        <div className="flex items-center justify-between border-b border-[#002D62]/10 px-4 py-4">
          <span className="text-sm font-semibold text-[#002D62]">
            Citizen Portal
          </span>
          <button
            type="button"
            onClick={closeMenu}
            className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-[#002D62]/20 bg-white text-[#002D62] transition-colors hover:bg-[#EFF6FF]"
            aria-label="Close citizen navigation"
          >
            <X className="h-5 w-5" aria-hidden />
          </button>
        </div>

        <nav
          className="flex-1 overflow-y-auto px-4 py-4"
          aria-label="Citizen dashboard navigation"
        >
          <ul className="space-y-1">
            {CITIZEN_NAV_ITEMS.map((item) => {
              const active = isCitizenNavItemActive(pathname, item.href);
              const Icon = item.icon;
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    className={linkClass(active)}
                    onClick={closeMenu}
                    aria-current={active ? "page" : undefined}
                  >
                    <Icon className="h-5 w-5 shrink-0" aria-hidden />
                    <span className="min-w-0 flex-1">{item.label}</span>
                    {active ? (
                      <span className="text-xs font-semibold uppercase tracking-wide text-[#0B3FE8]">
                        Active
                      </span>
                    ) : null}
                  </Link>
                </li>
              );
            })}
          </ul>

          {showReportAction ? (
            <div className="mt-6 border-t border-slate-200 pt-4">
              <Link
                href="/dashboard/citizen/report-new"
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-[#B91C1C] px-4 py-2.5 text-sm font-semibold text-white shadow-sm shadow-[#B91C1C]/20 transition-colors hover:bg-[#991B1B]"
                onClick={closeMenu}
              >
                <Plus className="h-5 w-5" aria-hidden />
                Report New Incident
              </Link>
            </div>
          ) : null}
        </nav>
      </aside>
    </div>
  );
}
