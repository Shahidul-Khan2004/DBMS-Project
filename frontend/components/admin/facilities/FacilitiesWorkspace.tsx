"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { AdminPageHeader } from "@/components/admin/AdminPageHeader";
import { CreateFacilityDialog } from "@/components/admin/facilities/CreateFacilityDialog";
import { FacilityListRow } from "@/components/admin/facilities/FacilityListRow";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { listAdminFacilities } from "@/lib/admin-facility-api";
import type { AdminFacilityListItem } from "@/types/admin-facility";

function sortFacilitiesByName(items: AdminFacilityListItem[]) {
  return [...items].sort((a, b) => a.name.localeCompare(b.name));
}

type FacilitiesListPanelProps = {
  sectionId: string;
  title: string;
  countLabel: string;
  facilities: AdminFacilityListItem[];
  emptyMessage: string;
  isLoading?: boolean;
};

function FacilitiesListPanel({
  sectionId,
  title,
  countLabel,
  facilities,
  emptyMessage,
  isLoading = false,
}: FacilitiesListPanelProps) {
  return (
    <section
      aria-labelledby={sectionId}
      className="flex min-h-0 min-w-0 flex-col rounded-xl border border-slate-200/80 bg-white shadow-sm lg:overflow-hidden"
    >
      <div className="flex shrink-0 flex-wrap items-baseline justify-between gap-2 border-b border-slate-100 px-3 py-2.5 lg:px-4">
        <h3 id={sectionId} className="text-sm font-semibold text-slate-900">
          {title}
        </h3>
        <p className="text-xs text-slate-600">{countLabel}</p>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain p-3 lg:p-4">
        {isLoading && facilities.length === 0 ? (
          <LoadingSkeleton lines={5} />
        ) : facilities.length === 0 ? (
          <p className="py-6 text-center text-xs text-slate-500">{emptyMessage}</p>
        ) : (
          <ul className="space-y-2">
            {facilities.map((facility) => (
              <FacilityListRow
                key={facility.publicUuid}
                facility={facility}
                showStatusBadge={false}
              />
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

export function FacilitiesWorkspace() {
  const router = useRouter();
  const [facilities, setFacilities] = useState<AdminFacilityListItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);

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

  const { activeFacilities, inactiveFacilities } = useMemo(() => {
    const active: AdminFacilityListItem[] = [];
    const inactive: AdminFacilityListItem[] = [];
    for (const facility of facilities) {
      if (facility.isActive) active.push(facility);
      else inactive.push(facility);
    }
    return {
      activeFacilities: sortFacilitiesByName(active),
      inactiveFacilities: sortFacilitiesByName(inactive),
    };
  }, [facilities]);

  const resultLabel = useMemo(() => {
    const total = facilities.length;
    if (total === 0) return "0 facilities";
    const activeCount = activeFacilities.length;
    const inactiveCount = inactiveFacilities.length;
    if (inactiveCount === 0) {
      return activeCount === 1 ? "1 active facility" : `${activeCount} active facilities`;
    }
    if (activeCount === 0) {
      return inactiveCount === 1
        ? "1 inactive facility"
        : `${inactiveCount} inactive facilities`;
    }
    return `${total} facilities · ${activeCount} active, ${inactiveCount} inactive`;
  }, [facilities.length, activeFacilities.length, inactiveFacilities.length]);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2 lg:overflow-hidden">
      <AdminPageHeader
        title="Facilities"
        subtitle="Manage shelters, hospitals, relief hubs, warehouses, and support facilities."
        action={
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-sm text-slate-600">{resultLabel}</p>
            <Button type="button" size="sm" onClick={() => setCreateOpen(true)}>
              + Add Facility
            </Button>
          </div>
        }
      />

      {error ? <ErrorAlert message={error} /> : null}

      {!isLoading && facilities.length === 0 ? (
        <div className="flex min-h-0 flex-1 flex-col items-center justify-center rounded-xl border border-slate-200/80 bg-white px-4 py-12 shadow-sm">
          <p className="text-center text-sm text-slate-600">No facilities yet.</p>
        </div>
      ) : (
        <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)] lg:overflow-hidden">
          <FacilitiesListPanel
            sectionId="facilities-active-heading"
            title="Active facilities"
            countLabel={
              activeFacilities.length === 1
                ? "1 active"
                : `${activeFacilities.length} active`
            }
            facilities={activeFacilities}
            emptyMessage="No active facilities."
            isLoading={isLoading}
          />
          <FacilitiesListPanel
            sectionId="facilities-inactive-heading"
            title="Inactive facilities"
            countLabel={
              inactiveFacilities.length === 1
                ? "1 inactive"
                : `${inactiveFacilities.length} inactive`
            }
            facilities={inactiveFacilities}
            emptyMessage="No inactive facilities."
            isLoading={isLoading}
          />
        </div>
      )}

      <CreateFacilityDialog
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        onSuccess={(facility) => {
          void loadFacilities();
          router.push(
            `/dashboard/admin/facilities/${encodeURIComponent(facility.publicUuid)}`,
          );
        }}
      />
    </div>
  );
}
