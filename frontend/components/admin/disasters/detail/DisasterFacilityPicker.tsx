"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { listAdminFacilities } from "@/lib/admin-facility-api";
import { formatFacilityTypeLabel } from "@/lib/admin-facility-format";
import type { AdminFacilityListItem } from "@/types/admin-facility";

const SHELTER_TYPE_CODES = new Set([
  "shelter",
  "school_shelter_capable",
  "community_center",
  "hospital",
  "clinic",
]);

const HUB_TYPE_CODES = new Set(["warehouse", "relief_center"]);

type DisasterFacilityPickerProps = {
  mode: "shelter" | "hub";
  selectedFacilityPublicUuid: string;
  onSelect: (facilityPublicUuid: string) => void;
  disabled?: boolean;
};

export function DisasterFacilityPicker({
  mode,
  selectedFacilityPublicUuid,
  onSelect,
  disabled = false,
}: DisasterFacilityPickerProps) {
  const [facilities, setFacilities] = useState<AdminFacilityListItem[]>([]);
  const [query, setQuery] = useState("");
  const [isLoading, setIsLoading] = useState(true);

  const loadFacilities = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await listAdminFacilities();
      const allowedTypes = mode === "shelter" ? SHELTER_TYPE_CODES : HUB_TYPE_CODES;
      setFacilities(
        (data.facilities ?? []).filter(
          (f) => f.isActive && allowedTypes.has(f.facilityTypeCode),
        ),
      );
    } catch {
      setFacilities([]);
    } finally {
      setIsLoading(false);
    }
  }, [mode]);

  useEffect(() => {
    void loadFacilities();
  }, [loadFacilities]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return facilities;
    return facilities.filter(
      (f) =>
        f.name.toLowerCase().includes(q) ||
        f.facilityCode.toLowerCase().includes(q),
    );
  }, [facilities, query]);

  if (isLoading) {
    return <LoadingSkeleton lines={4} />;
  }

  return (
    <div className="space-y-2">
      <input
        type="search"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Search facilities by name or code"
        className={triageFieldClassName}
        disabled={disabled}
      />
      <p className="text-xs text-slate-500">
        Showing {mode === "shelter" ? "shelter-capable" : "warehouse/relief"}{" "}
        facility types. Backend validates capabilities on activation.
      </p>
      <ul className="max-h-48 space-y-1 overflow-y-auto overscroll-y-contain rounded-lg border border-slate-200 p-1">
        {filtered.length === 0 ? (
          <li className="px-2 py-2 text-sm text-slate-600">No facilities found.</li>
        ) : (
          filtered.map((facility) => {
            const selected = facility.publicUuid === selectedFacilityPublicUuid;
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
                  <span className="font-medium">{facility.name}</span>
                  <span
                    className={
                      selected ? "text-white/80" : "text-slate-500"
                    }
                  >
                    {" "}
                    · {formatFacilityTypeLabel(facility.facilityTypeCode)}
                  </span>
                </button>
              </li>
            );
          })
        )}
      </ul>
    </div>
  );
}
