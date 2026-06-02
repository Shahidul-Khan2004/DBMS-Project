"use client";

import Link from "next/link";
import { ChevronRight } from "lucide-react";
import { getDispatcherClickableCardRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import {
  formatFacilityLocationSummary,
  formatFacilityTypeLabel,
} from "@/lib/admin-facility-format";
import { nationalDisasterFacilityDetailPath } from "@/lib/admin-national-disaster-routes";
import type { AdminFacilityListItem } from "@/types/admin-facility";

type FacilityListRowProps = {
  facility: AdminFacilityListItem;
  /** Hide when the parent list is already split by active/inactive. */
  showStatusBadge?: boolean;
};

export function FacilityListRow({
  facility,
  showStatusBadge = true,
}: FacilityListRowProps) {
  const locationHint =
    facility.location != null
      ? formatFacilityLocationSummary(facility.location)
      : null;

  return (
    <li>
      <Link
        href={nationalDisasterFacilityDetailPath(facility.publicUuid)}
        className={`group flex w-full flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-100 px-3 py-2.5 text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[#002D62] ${getDispatcherClickableCardRowClasses()}`}
      >
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-slate-900">{facility.name}</p>
          <p className="mt-0.5 text-xs text-slate-600">
            {facility.facilityCode} ·{" "}
            {formatFacilityTypeLabel(facility.facilityTypeCode)}
          </p>
          {locationHint ? (
            <p className="mt-0.5 line-clamp-1 text-xs text-slate-500">
              {locationHint}
            </p>
          ) : null}
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          {showStatusBadge ? (
            <Badge
              size="compact"
              tone={facility.isActive ? "success" : "neutral"}
            >
              {facility.isActive ? "Active" : "Inactive"}
            </Badge>
          ) : null}
          <span className="flex items-center gap-0.5 text-xs font-medium text-[#002D62]">
            Manage
            <ChevronRight
              className="h-4 w-4 transition-transform group-hover:translate-x-0.5"
              aria-hidden
            />
          </span>
        </div>
      </Link>
    </li>
  );
}
