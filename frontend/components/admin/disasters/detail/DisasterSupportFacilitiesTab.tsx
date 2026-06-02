"use client";

import { useMemo } from "react";
import Link from "next/link";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import {
  getAffectedAdminAreaIds,
  isFacilityInAffectedArea,
} from "@/components/admin/disasters/detail/disasterFacilityPickerHelpers";
import {
  sortFacilitiesByName,
  SUPPORT_FACILITY_TYPES,
} from "@/components/admin/disasters/detail/disasterResourceHelpers";
import {
  formatFacilityLocationSummary,
  formatFacilityTypeLabel,
} from "@/lib/admin-facility-format";
import { nationalDisasterFacilityDetailPath } from "@/lib/admin-national-disaster-routes";
import type { AdminFacilityListItem } from "@/types/admin-facility";
import type { DisasterDashboardResponse } from "@/types/disaster-operations";

type DisasterSupportFacilitiesTabProps = {
  dashboard: DisasterDashboardResponse;
  facilities: AdminFacilityListItem[];
};

export function DisasterSupportFacilitiesTab({
  dashboard,
  facilities,
}: DisasterSupportFacilitiesTabProps) {
  const affectedAdminAreaIds = useMemo(
    () => getAffectedAdminAreaIds(dashboard),
    [dashboard],
  );

  const supportFacilities = useMemo(
    () =>
      sortFacilitiesByName(
        facilities.filter(
          (f) =>
            f.isActive &&
            SUPPORT_FACILITY_TYPES.has(f.facilityTypeCode) &&
            isFacilityInAffectedArea(f, affectedAdminAreaIds),
        ),
      ),
    [facilities, affectedAdminAreaIds],
  );

  return (
    <CommandSectionCard title="Support facilities in affected areas">
      <p className="mb-3 text-xs text-slate-600">
        Hospitals, clinics, and other support sites for situational awareness.
        Activate shelters and relief hubs from their dedicated tabs.
      </p>
      {supportFacilities.length === 0 ? (
        <p className="text-sm text-slate-600">
          No support facilities found inside affected areas.
        </p>
      ) : (
        <ul className="max-h-[min(24rem,50vh)] space-y-1 overflow-y-auto overscroll-y-contain">
          {supportFacilities.map((facility) => (
            <li
              key={facility.publicUuid}
              className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-slate-100 px-3 py-2 text-sm"
            >
              <div className="min-w-0">
                <p className="font-medium text-slate-900">{facility.name}</p>
                <p className="text-xs text-slate-600">
                  {facility.facilityCode} ·{" "}
                  {formatFacilityTypeLabel(facility.facilityTypeCode)}
                </p>
                {formatFacilityLocationSummary(facility.location) ? (
                  <p className="text-xs text-slate-500">
                    {formatFacilityLocationSummary(facility.location)}
                  </p>
                ) : null}
              </div>
              <Link
                href={nationalDisasterFacilityDetailPath(facility.publicUuid)}
                className="shrink-0 text-xs font-medium text-[#002D62] hover:underline"
              >
                Open Facility Details →
              </Link>
            </li>
          ))}
        </ul>
      )}
    </CommandSectionCard>
  );
}
