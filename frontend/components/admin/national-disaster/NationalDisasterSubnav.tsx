"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  isNationalDisasterFacilitiesRoute,
  isNationalDisasterLandingRoute,
  nationalDisasterFacilitiesPath,
  nationalDisasterLandingPath,
} from "@/lib/admin-national-disaster-routes";

const SECTIONS = [
  {
    label: "Disaster Command",
    href: nationalDisasterLandingPath(),
    isActive: isNationalDisasterLandingRoute,
  },
  {
    label: "Facility Registry",
    href: nationalDisasterFacilitiesPath(),
    isActive: isNationalDisasterFacilitiesRoute,
  },
] as const;

export function NationalDisasterSectionSwitch() {
  const pathname = usePathname();

  return (
    <div
      role="tablist"
      aria-label="National disaster sections"
      className="inline-flex shrink-0 rounded-lg border border-slate-200 bg-slate-100/80 p-0.5"
    >
      {SECTIONS.map((section) => {
        const active = section.isActive(pathname);
        return (
          <Link
            key={section.href}
            href={section.href}
            role="tab"
            aria-selected={active}
            aria-current={active ? "page" : undefined}
            className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
              active
                ? "bg-white text-slate-900 shadow-sm"
                : "text-slate-600 hover:text-slate-900"
            }`}
          >
            {section.label}
          </Link>
        );
      })}
    </div>
  );
}

/** @deprecated Use NationalDisasterSectionSwitch */
export const NationalDisasterSubnav = NationalDisasterSectionSwitch;
