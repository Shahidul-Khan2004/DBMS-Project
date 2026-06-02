"use client";

import { useMemo, useState } from "react";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import {
  formatFacilityLocationSummary,
  formatFacilityTypeLabel,
} from "@/lib/admin-facility-format";
import {
  filterFacilitiesByAllowList,
  filterFacilitiesForSearch,
  isFacilityInAffectedArea,
  isReliefHubEligibleFacility,
  isShelterEligibleFacility,
} from "@/components/admin/disasters/detail/disasterFacilityPickerHelpers";
import type { AdminFacilityListItem } from "@/types/admin-facility";

type DisasterFacilityPickerProps = {
  mode: "shelter" | "hub";
  facilities: AdminFacilityListItem[];
  affectedAdminAreaIds: Set<number>;
  selectedFacilityPublicUuid: string;
  onSelect: (facilityPublicUuid: string) => void;
  disabled?: boolean;
  /** Deactivated-only panel: search within allow-list, no in-area preferred list. */
  overrideOnly?: boolean;
  /** When set, only these facility public UUIDs appear in the list. */
  allowedFacilityPublicUuids?: ReadonlySet<string>;
};

function applyAllowList(
  facilities: AdminFacilityListItem[],
  allowedFacilityPublicUuids?: ReadonlySet<string>,
) {
  return filterFacilitiesByAllowList(facilities, allowedFacilityPublicUuids);
}

export function DisasterFacilityPicker({
  mode,
  facilities,
  affectedAdminAreaIds,
  selectedFacilityPublicUuid,
  onSelect,
  disabled = false,
  overrideOnly = false,
  allowedFacilityPublicUuids,
}: DisasterFacilityPickerProps) {
  const [query, setQuery] = useState("");
  const eligibilityFn =
    mode === "shelter" ? isShelterEligibleFacility : isReliefHubEligibleFacility;
  const reactivateOnly = overrideOnly && allowedFacilityPublicUuids != null;

  const preferredFacilities = useMemo(
    () =>
      applyAllowList(
        facilities.filter(
          (facility) =>
            facility.isActive &&
            eligibilityFn(facility) &&
            isFacilityInAffectedArea(facility, affectedAdminAreaIds),
        ),
        allowedFacilityPublicUuids,
      ),
    [facilities, affectedAdminAreaIds, eligibilityFn, allowedFacilityPublicUuids],
  );

  const searchResults = useMemo(
    () =>
      applyAllowList(
        filterFacilitiesForSearch(facilities, query, eligibilityFn),
        allowedFacilityPublicUuids,
      ),
    [facilities, query, eligibilityFn, allowedFacilityPublicUuids],
  );

  const isSearchMode = query.trim().length > 0;
  const displayedFacilities = overrideOnly
    ? searchResults
    : isSearchMode
      ? searchResults
      : preferredFacilities;

  const facilityKind = mode === "shelter" ? "shelter" : "relief hub";

  return (
    <div className="space-y-2">
      {!overrideOnly ? (
        <p className="text-xs text-slate-500">
          {mode === "shelter"
            ? "Showing shelter facilities inside the affected areas first. Use search for manual override."
            : "Showing relief facilities inside the affected areas first. Use search for manual override."}
        </p>
      ) : reactivateOnly ? (
        <p className="text-xs text-slate-500">
          Select a deactivated {facilityKind} to restore it to the active list. Search filters
          within deactivated facilities only.
        </p>
      ) : (
        <p className="text-xs text-slate-500">
          Search eligible facilities by name, code, type, or area. Results outside
          affected areas can still be activated.
        </p>
      )}
      <label
        htmlFor={mode === "shelter" ? "shelter-facility-search" : "hub-facility-search"}
        className="text-xs font-medium text-slate-700"
      >
        {reactivateOnly
          ? `Search deactivated ${facilityKind}s`
          : mode === "shelter"
            ? "Search all shelter facilities"
            : "Search all relief hub facilities"}
      </label>
      <input
        id={mode === "shelter" ? "shelter-facility-search" : "hub-facility-search"}
        type="search"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Type facility name, code, type, or area"
        className={triageFieldClassName}
        disabled={disabled}
      />

      <ul className="max-h-56 space-y-1 overflow-y-auto overscroll-y-contain rounded-lg border border-slate-200 p-1">
        {displayedFacilities.length === 0 ? (
          reactivateOnly ? (
            <li className="px-2 py-2 text-sm text-slate-600">
              {isSearchMode
                ? `No deactivated ${facilityKind}s match your search.`
                : `No deactivated ${facilityKind}s for this disaster.`}
            </li>
          ) : overrideOnly ? (
            <li className="px-2 py-2 text-sm text-slate-600">
              {isSearchMode
                ? "No eligible facilities match your search."
                : "Type to search eligible facilities for manual override."}
            </li>
          ) : isSearchMode ? (
            <li className="px-2 py-2 text-sm text-slate-600">
              No eligible facilities match your search.
            </li>
          ) : (
            <li className="space-y-1 px-2 py-2 text-sm text-slate-600">
              <p>No matching facilities found inside the affected areas.</p>
              <p className="text-xs text-slate-500">
                Search all eligible facilities for manual override.
              </p>
            </li>
          )
        ) : (
          displayedFacilities.map((facility) => {
            const selected = facility.publicUuid === selectedFacilityPublicUuid;
            const isInArea = isFacilityInAffectedArea(facility, affectedAdminAreaIds);
            const locationSummary = formatFacilityLocationSummary(facility.location);
            return (
              <li key={facility.publicUuid}>
                <button
                  type="button"
                  disabled={disabled}
                  onClick={() => onSelect(facility.publicUuid)}
                  className={`w-full rounded-md px-2 py-2 text-left text-sm transition-colors ${
                    selected
                      ? "bg-[#002D62] text-white"
                      : "text-slate-900 hover:bg-slate-50"
                  }`}
                >
                  <span className="flex items-center justify-between gap-2">
                    <span className="font-medium">{facility.name}</span>
                    {!reactivateOnly ? (
                      <span
                        className={`rounded-full px-1.5 py-0.5 text-[10px] font-medium ${
                          selected
                            ? "bg-white/20 text-white"
                            : isInArea
                              ? "bg-emerald-50 text-emerald-700"
                              : "bg-amber-50 text-amber-700"
                        }`}
                      >
                        {isInArea ? "Affected area match" : "Outside affected area"}
                      </span>
                    ) : null}
                  </span>
                  <span className={selected ? "text-white/80" : "text-slate-500"}>
                    {facility.facilityCode} ·{" "}
                    {formatFacilityTypeLabel(facility.facilityTypeCode)}
                  </span>
                  {locationSummary ? (
                    <span className={selected ? "block text-white/80" : "block text-slate-500"}>
                      {locationSummary}
                    </span>
                  ) : null}
                </button>
              </li>
            );
          })
        )}
      </ul>
    </div>
  );
}
