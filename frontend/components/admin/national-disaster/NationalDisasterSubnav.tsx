"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  isNationalDisasterFacilitiesRoute,
  isNationalDisasterLandingRoute,
  nationalDisasterFacilitiesPath,
  nationalDisasterLandingPath,
} from "@/lib/admin-national-disaster-routes";

const SUBNAV_TABS = [
  { label: "Disaster Command", href: nationalDisasterLandingPath(), isActive: isNationalDisasterLandingRoute },
  {
    label: "Facility Registry",
    href: nationalDisasterFacilitiesPath(),
    isActive: isNationalDisasterFacilitiesRoute,
  },
] as const;

export function NationalDisasterSubnav() {
  const pathname = usePathname();

  return (
    <nav
      aria-label="National disaster sections"
      className="flex shrink-0 flex-wrap gap-2"
    >
      {SUBNAV_TABS.map((tab) => {
        const active = tab.isActive(pathname);
        return (
          <Link
            key={tab.href}
            href={tab.href}
            className={`shrink-0 rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
              active
                ? "bg-[#002D62] text-white shadow-sm"
                : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
            }`}
            aria-current={active ? "page" : undefined}
          >
            {tab.label}
          </Link>
        );
      })}
    </nav>
  );
}
