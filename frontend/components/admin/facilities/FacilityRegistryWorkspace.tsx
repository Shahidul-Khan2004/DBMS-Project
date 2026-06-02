"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { AdminPageHeader } from "@/components/admin/AdminPageHeader";
import { CreateFacilityDialog } from "@/components/admin/facilities/CreateFacilityDialog";
import { FacilityListRow } from "@/components/admin/facilities/FacilityListRow";
import { NationalDisasterSubnav } from "@/components/admin/national-disaster/NationalDisasterSubnav";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import {
  FACILITY_REGISTRY_TABS,
  filterFacilitiesByRegistryTab,
  type FacilityRegistryTab,
} from "@/lib/admin-facility-readiness";
import { nationalDisasterFacilityDetailPath } from "@/lib/admin-national-disaster-routes";
import { listAdminFacilities } from "@/lib/admin-facility-api";
import type { AdminFacilityListItem } from "@/types/admin-facility";

function sortFacilitiesByName(items: AdminFacilityListItem[]) {
  return [...items].sort((a, b) => a.name.localeCompare(b.name));
}

export function FacilityRegistryWorkspace() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [facilities, setFacilities] = useState<AdminFacilityListItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<FacilityRegistryTab>("all");

  const loadFacilities = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await listAdminFacilities();
      setFacilities(data.facilities);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load facilities.",
      );
      setFacilities([]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadFacilities();
  }, [loadFacilities]);

  useEffect(() => {
    if (searchParams.get("create") === "1") {
      setCreateOpen(true);
    }
  }, [searchParams]);

  const filteredFacilities = useMemo(
    () => sortFacilitiesByName(filterFacilitiesByRegistryTab(facilities, activeTab)),
    [facilities, activeTab],
  );

  const resultLabel =
    filteredFacilities.length === 1
      ? "1 facility"
      : `${filteredFacilities.length} facilities`;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3 lg:overflow-hidden">
      <AdminPageHeader
        title="Facility Registry"
        subtitle="Manage shelters, hospitals, relief hubs, warehouses, and support facilities for disaster response. This is the permanent facility database; shelters and relief hubs activated for a specific disaster are managed from Disaster Command."
        action={
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-sm text-slate-600">{resultLabel}</p>
            <Button type="button" size="sm" onClick={() => setCreateOpen(true)}>
              + Add Facility
            </Button>
          </div>
        }
      />

      <NationalDisasterSubnav />

      <div
        className="flex shrink-0 flex-wrap gap-2"
        role="tablist"
        aria-label="Facility filters"
      >
        {FACILITY_REGISTRY_TABS.map((tab) => {
          const active = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={active}
              onClick={() => setActiveTab(tab.id)}
              className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                active
                  ? "bg-[#002D62] text-white shadow-sm"
                  : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
              }`}
            >
              {tab.label}
            </button>
          );
        })}
      </div>

      {error ? <ErrorAlert message={error} /> : null}

      <section
        aria-label="Facility list"
        className="flex min-h-0 flex-1 flex-col rounded-xl border border-slate-200/80 bg-white shadow-sm lg:overflow-hidden"
      >
        <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain p-3 lg:p-4">
          {isLoading && facilities.length === 0 ? (
            <LoadingSkeleton lines={6} />
          ) : filteredFacilities.length === 0 ? (
            <p className="py-8 text-center text-sm text-slate-600">
              No facilities match this filter.
            </p>
          ) : (
            <ul className="space-y-1">
              {filteredFacilities.map((facility) => (
                <FacilityListRow key={facility.publicUuid} facility={facility} />
              ))}
            </ul>
          )}
        </div>
      </section>

      <CreateFacilityDialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onSuccess={(facility) => {
          void loadFacilities();
          router.push(nationalDisasterFacilityDetailPath(facility.publicUuid));
        }}
      />
    </div>
  );
}
