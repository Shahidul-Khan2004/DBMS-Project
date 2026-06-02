"use client";

import Link from "next/link";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { Button } from "@/components/ui/Button";
import {
  formatFacilityLocationSummary,
  formatFacilityTypeLabel,
} from "@/lib/admin-facility-format";
import { nationalDisasterFacilityDetailPath } from "@/lib/admin-national-disaster-routes";
import type { AdminFacilityListItem } from "@/types/admin-facility";

type DisasterPotentialFacilitiesPanelProps = {
  title: string;
  facilities: AdminFacilityListItem[];
  emptyPrimary: string;
  emptySecondary: string;
  isReadOnly: boolean;
  activateLabel?: string;
  onActivate?: (facilityPublicUuid: string) => void;
  showActivateOnRows?: boolean;
  isActivatingFacilityPublicUuid?: string | null;
};

export function DisasterPotentialFacilitiesPanel({
  title,
  facilities,
  emptyPrimary,
  emptySecondary,
  isReadOnly,
  activateLabel,
  onActivate,
  showActivateOnRows = true,
  isActivatingFacilityPublicUuid = null,
}: DisasterPotentialFacilitiesPanelProps) {
  return (
    <CommandSectionCard title={title}>
      {facilities.length === 0 ? (
        <div className="space-y-1 text-sm text-slate-600">
          <p>{emptyPrimary}</p>
          <p className="text-xs text-slate-500">{emptySecondary}</p>
        </div>
      ) : (
        <ul className="max-h-56 space-y-1 overflow-y-auto overscroll-y-contain">
          {facilities.map((facility) => (
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
              <div className="flex shrink-0 flex-wrap gap-1">
                {!isReadOnly && showActivateOnRows && activateLabel && onActivate ? (
                  <Button
                    type="button"
                    size="sm"
                    isLoading={isActivatingFacilityPublicUuid === facility.publicUuid}
                    disabled={
                      isActivatingFacilityPublicUuid != null &&
                      isActivatingFacilityPublicUuid !== facility.publicUuid
                    }
                    onClick={() => onActivate(facility.publicUuid)}
                  >
                    {activateLabel}
                  </Button>
                ) : null}
                <Link
                  href={nationalDisasterFacilityDetailPath(facility.publicUuid)}
                  className="inline-flex items-center rounded-md border border-slate-200 px-2.5 py-1 text-xs font-medium text-[#002D62] hover:bg-slate-50"
                >
                  Open details
                </Link>
              </div>
            </li>
          ))}
        </ul>
      )}
    </CommandSectionCard>
  );
}
