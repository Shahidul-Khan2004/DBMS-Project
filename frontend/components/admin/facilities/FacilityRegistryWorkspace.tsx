"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { CreateFacilityDialog } from "@/components/admin/facilities/CreateFacilityDialog";
import {
  computeFacilityRegistryTabCounts,
  FacilityRegistryFilterNav,
} from "@/components/admin/facilities/FacilityRegistryFilterNav";
import { FacilityListRow } from "@/components/admin/facilities/FacilityListRow";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import {
  filterFacilitiesByRegistryTab,
  type FacilityRegistryTab,
} from "@/lib/admin-facility-readiness";
import {
  nationalDisasterFacilityDetailPath,
  nationalDisasterLandingPath,
} from "@/lib/admin-national-disaster-routes";
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

  const tabCounts = useMemo(
    () => computeFacilityRegistryTabCounts(facilities),
    [facilities],
  );

  const filteredFacilities = useMemo(
    () => sortFacilitiesByName(filterFacilitiesByRegistryTab(facilities, activeTab)),
    [facilities, activeTab],
  );

  const resultLabel =
    filteredFacilities.length === 1
      ? "1 facility"
      : `${filteredFacilities.length} facilities`;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2 lg:overflow-hidden">
      <div className="shrink-0 space-y-0.5">
        <Link
          href={nationalDisasterLandingPath()}
          className="text-sm font-medium text-[#002D62] hover:underline"
        >
          ← Disaster Command
        </Link>
      </div>

      {error ? <ErrorAlert message={error} /> : null}

      <section
        aria-label="Facility list"
        className="flex min-h-0 flex-1 flex-col rounded-xl border border-slate-200/80 bg-white shadow-sm lg:overflow-hidden"
      >
        <div className="flex shrink-0 flex-wrap items-center justify-between gap-2 border-b border-slate-100 px-3 py-2.5 lg:px-4">
          <div className="flex min-w-0 flex-wrap items-baseline gap-2">
            <h2 className="text-lg font-semibold text-slate-900">
              Facility Registry
            </h2>
            <p className="text-sm text-slate-600">{resultLabel}</p>
          </div>
          <Button type="button" size="sm" onClick={() => setCreateOpen(true)}>
            + Add Facility
          </Button>
        </div>
        <div className="shrink-0 border-b border-slate-100 px-3 py-2.5 lg:hidden">
          <FacilityRegistryFilterNav
            activeTab={activeTab}
            onSelect={setActiveTab}
            tabCounts={tabCounts}
            layout="horizontal"
          />
        </div>

        <div className="flex min-h-0 flex-1 flex-col lg:grid lg:grid-cols-[minmax(11rem,13rem)_minmax(0,1fr)] lg:overflow-hidden">
          <div className="hidden min-h-0 shrink-0 border-slate-100 lg:block lg:border-r lg:overflow-y-auto lg:overscroll-y-contain">
            <FacilityRegistryFilterNav
              activeTab={activeTab}
              onSelect={setActiveTab}
              tabCounts={tabCounts}
              layout="vertical"
            />
          </div>

          <div
            className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain p-3 lg:p-4"
            role="tabpanel"
            aria-label={`${activeTab} facilities`}
          >
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
