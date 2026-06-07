"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Menu, Plus } from "lucide-react";
import { useCitizenNav } from "@/components/citizen/CitizenNavContext";
import {
  CITIZEN_NAV_ITEMS,
  getCitizenNavSectionLabel,
  isCitizenNavItemActive,
} from "@/components/citizen/citizenNavSection";

export function CitizenTopNav({
  showReportAction,
}: {
  showReportAction: boolean;
}) {
  const pathname = usePathname();
  const { openMenu } = useCitizenNav();
  const sectionLabel = getCitizenNavSectionLabel(pathname);

  return (
    <>
      <nav
        aria-label="Citizen dashboard navigation"
        className="hidden h-12 shrink-0 items-center gap-3 border-b border-slate-200/80 bg-white/90 px-4 backdrop-blur-sm lg:flex sm:px-6 lg:px-8 2xl:px-10"
      >
        <div className="flex min-w-0 flex-1 items-center gap-1">
          {CITIZEN_NAV_ITEMS.map((item) => {
            const active = isCitizenNavItemActive(pathname, item.href);
            const Icon = item.icon;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`inline-flex shrink-0 items-center gap-2 whitespace-nowrap rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                  active
                    ? "bg-[#002D62] text-white shadow-sm"
                    : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
                }`}
                aria-current={active ? "page" : undefined}
              >
                <Icon className="h-4 w-4" aria-hidden />
                {item.label}
              </Link>
            );
          })}
        </div>
        {showReportAction ? (
          <Link
            href="/dashboard/citizen/report-new"
            className="inline-flex shrink-0 items-center justify-center gap-2 rounded-md border border-[#991B1B] bg-[#B91C1C] px-3 py-1.5 text-sm font-medium text-white shadow-sm transition-colors hover:bg-[#991B1B]"
          >
            <Plus className="h-4 w-4" aria-hidden />
            <span className="hidden xl:inline">Report New Incident</span>
            <span className="xl:hidden">Report</span>
          </Link>
        ) : null}
      </nav>

      <div
        aria-label="Current citizen section"
        className="flex h-11 shrink-0 items-center justify-between gap-3 border-b border-slate-200/80 bg-white/90 px-4 backdrop-blur-sm sm:px-6 lg:hidden lg:px-8"
      >
        <span className="min-w-0 truncate text-sm font-semibold text-slate-800">
          {sectionLabel}
        </span>
        <div className="flex shrink-0 items-center gap-2">
          {showReportAction ? (
            <Link
              href="/dashboard/citizen/report-new"
              className="inline-flex h-9 items-center justify-center gap-1.5 rounded-md bg-[#B91C1C] px-3 text-xs font-semibold text-white shadow-sm shadow-[#B91C1C]/20 transition-colors hover:bg-[#991B1B] sm:px-4 sm:text-sm"
            >
              <Plus className="h-4 w-4 sm:h-5 sm:w-5" aria-hidden />
              <span className="hidden min-[400px]:inline">Report</span>
            </Link>
          ) : null}
          <button
            type="button"
            onClick={openMenu}
            className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl text-[#002D62] transition-colors hover:bg-[#EFF6FF]"
            aria-label="Open citizen navigation"
          >
            <Menu className="h-5 w-5" aria-hidden />
          </button>
        </div>
      </div>
    </>
  );
}
