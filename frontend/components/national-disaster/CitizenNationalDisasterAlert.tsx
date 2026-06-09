"use client";

import Link from "next/link";
import { AlertTriangle } from "lucide-react";
import { useDeclaredNationalDisasters } from "@/hooks/useDeclaredNationalDisasters";
import {
  formatDisasterDetail,
  formatDisasterGuidance,
} from "@/lib/national-disaster-alert";

export function CitizenNationalDisasterAlert() {
  const { disasters } = useDeclaredNationalDisasters();

  if (disasters.length === 0) return null;

  const primary = disasters[0];
  const disasterType =
    formatDisasterDetail(primary.disaster_type_name) ?? "Disaster";
  const severity =
    formatDisasterDetail(primary.severity_level) ?? "Unspecified";
  const guidance = formatDisasterGuidance(primary.public_guidance);
  const extraCount = disasters.length - 1;

  return (
    <aside
      className="shrink-0 border-b border-[#B91C1C]/20 bg-red-50/80 px-4 py-3 sm:px-6 lg:px-8 2xl:px-10"
      aria-label="National emergency alert"
      role="status"
    >
      <div className="mx-auto flex w-full max-w-[1600px] flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex min-w-0 flex-1 gap-3 border-l-4 border-[#B91C1C] pl-3">
          <AlertTriangle
            className="mt-0.5 h-5 w-5 shrink-0 text-[#B91C1C]"
            aria-hidden
          />
          <div className="min-w-0">
            <p className="text-xs font-semibold uppercase tracking-wide text-[#991B1B]">
              National emergency in effect
            </p>
            <p className="mt-0.5 truncate text-sm font-bold text-[#002D62] sm:text-base">
              {primary.title}
            </p>
            <p className="mt-0.5 line-clamp-2 text-xs leading-5 text-[#42547A] sm:text-sm">
              {disasterType} · Severity {severity}
              {guidance ? ` · ${guidance}` : ""}
            </p>
            {extraCount > 0 ? (
              <p className="mt-1 text-xs font-medium text-[#991B1B]">
                +{extraCount} more active emergenc
                {extraCount > 1 ? "ies" : "y"}
              </p>
            ) : null}
          </div>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2 sm:justify-end">
          <Link
            href="/dashboard/citizen/report-new"
            className="inline-flex items-center justify-center rounded-xl bg-[#B91C1C] px-3 py-2 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-[#991B1B] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62]"
          >
            Report incident
          </Link>
          <Link
            href="/#national-disaster"
            className="inline-flex items-center justify-center rounded-xl border-2 border-[#002D62] bg-white px-3 py-2 text-sm font-semibold text-[#002D62] transition-colors hover:bg-[#EFF6FF] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62]"
          >
            View guidance
          </Link>
        </div>
      </div>
    </aside>
  );
}
