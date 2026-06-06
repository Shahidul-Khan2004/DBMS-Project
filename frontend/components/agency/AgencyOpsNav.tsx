"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Menu } from "lucide-react";
import { useAgencyNav } from "@/components/agency/AgencyNavContext";
import {
  AGENCY_OPS_TABS,
  getAgencyOpsSectionLabel,
  isAgencyNationalDisasterRoute,
  isAgencyOpsTabActive,
} from "@/components/agency/agencyOpsSection";
import { DISPATCHER_EMERGENCY_ACTIVE_RING_CLASSES } from "@/components/dispatcher/emergencyColors";
import { agencyNationalDisasterLandingPath } from "@/lib/agency-national-disaster-routes";

const NATIONAL_DISASTER_LINK_CLASS =
  "inline-flex shrink-0 cursor-pointer items-center rounded-md border border-[#991B1B] bg-[#B91C1C] px-3 py-1.5 text-sm font-medium text-white shadow-sm transition-colors hover:bg-[#991B1B]";

export function AgencyOpsNav() {
  const pathname = usePathname();
  const { openMenu } = useAgencyNav();
  const sectionLabel = getAgencyOpsSectionLabel(pathname);
  const isNationalDisasterActive = isAgencyNationalDisasterRoute(pathname);

  return (
    <>
      <nav
        aria-label="Agency operations"
        className="hidden h-12 shrink-0 items-center gap-4 border-b border-slate-200/80 bg-white/90 px-4 backdrop-blur-sm xl:flex sm:px-6 lg:px-8"
      >
        <div className="flex min-w-0 flex-1 items-center gap-1">
          {AGENCY_OPS_TABS.map((tab) => {
            const active = isAgencyOpsTabActive(pathname, tab.href);
            return (
              <Link
                key={tab.href}
                href={tab.href}
                className={`shrink-0 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                  active
                    ? "bg-[#002D62] text-white shadow-sm"
                    : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
                }`}
              >
                {tab.label}
              </Link>
            );
          })}
        </div>
        <Link
          href={agencyNationalDisasterLandingPath()}
          className={`${NATIONAL_DISASTER_LINK_CLASS} ${
            isNationalDisasterActive ? DISPATCHER_EMERGENCY_ACTIVE_RING_CLASSES : ""
          }`}
          aria-current={isNationalDisasterActive ? "page" : undefined}
        >
          National Disaster
        </Link>
      </nav>

      <div
        aria-label="Current agency section"
        className="flex h-11 shrink-0 items-center justify-between gap-3 border-b border-slate-200/80 bg-white/90 px-4 backdrop-blur-sm xl:hidden sm:px-6 lg:px-8"
      >
        <span className="min-w-0 truncate text-sm font-semibold text-slate-800">
          {sectionLabel}
        </span>
        <button
          type="button"
          onClick={openMenu}
          className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl text-[#002D62] transition-colors hover:bg-[#EFF6FF]"
          aria-label="Open agency navigation"
        >
          <Menu className="h-5 w-5" aria-hidden />
        </button>
      </div>
    </>
  );
}
