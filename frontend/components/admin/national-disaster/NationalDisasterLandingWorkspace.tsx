"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { AdminPageHeader } from "@/components/admin/AdminPageHeader";
import { DisasterListRow } from "@/components/admin/disasters/DisasterListRow";
import { NationalDisasterSubnav } from "@/components/admin/national-disaster/NationalDisasterSubnav";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { computeFacilityReadinessStats } from "@/lib/admin-facility-readiness";
import {
  nationalDisasterDeclarePath,
  nationalDisasterFacilitiesPath,
} from "@/lib/admin-national-disaster-routes";
import { listAdminFacilities } from "@/lib/admin-facility-api";
import { listDisasters } from "@/lib/disaster-operations-api";
import type { AdminFacilityListItem } from "@/types/admin-facility";
import type { DisasterListItem } from "@/types/disaster-operations";

function ReadinessStat({
  label,
  value,
}: {
  label: string;
  value: number;
}) {
  return (
    <div className="rounded-lg border border-slate-100 bg-slate-50/80 px-3 py-2.5">
      <p className="text-xs font-medium text-slate-500">{label}</p>
      <p className="mt-0.5 text-lg font-semibold tabular-nums text-slate-900">
        {value}
      </p>
    </div>
  );
}

export function NationalDisasterLandingWorkspace() {
  const router = useRouter();
  const [disasters, setDisasters] = useState<DisasterListItem[]>([]);
  const [facilities, setFacilities] = useState<AdminFacilityListItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [disasterData, facilityData] = await Promise.all([
        listDisasters(),
        listAdminFacilities(),
      ]);
      setDisasters(disasterData.disasters);
      setFacilities(facilityData.facilities ?? []);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load national disaster data.",
      );
      setDisasters([]);
      setFacilities([]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadData();
  }, [loadData]);

  const readiness = computeFacilityReadinessStats(facilities);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-3 lg:overflow-hidden">
      <AdminPageHeader
        title="National Disaster Management"
        subtitle="Coordinate declared disasters, affected areas, facilities, shelters, relief, and agency responsibilities."
        action={
          <div className="flex flex-wrap items-center gap-2">
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={() => void loadData()}
              disabled={isLoading}
              aria-label="Refresh"
            >
              <RefreshCw
                className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`}
                aria-hidden
              />
              Refresh
            </Button>
            <Button
              type="button"
              variant="emergency"
              size="sm"
              onClick={() => router.push(nationalDisasterDeclarePath())}
            >
              + Declare Disaster
            </Button>
            <Button
              type="button"
              size="sm"
              onClick={() =>
                router.push(`${nationalDisasterFacilitiesPath()}?create=1`)
              }
            >
              + Add Facility
            </Button>
          </div>
        }
      />

      <NationalDisasterSubnav />

      {error ? <ErrorAlert message={error} /> : null}

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 lg:grid-cols-[minmax(0,55fr)_minmax(0,45fr)] lg:overflow-hidden">
        <section
          aria-labelledby="active-disasters-heading"
          className="flex min-h-0 min-w-0 flex-col rounded-xl border border-slate-200/80 bg-white shadow-sm lg:overflow-hidden"
        >
          <div className="flex shrink-0 items-baseline justify-between gap-2 border-b border-slate-100 px-3 py-2.5 lg:px-4">
            <h3
              id="active-disasters-heading"
              className="text-sm font-semibold text-slate-900"
            >
              Active & Recent Disasters
            </h3>
            <p className="text-xs text-slate-600">
              {disasters.length === 1
                ? "1 disaster"
                : `${disasters.length} disasters`}
            </p>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain p-3 lg:p-4">
            {isLoading && disasters.length === 0 ? (
              <LoadingSkeleton lines={6} />
            ) : disasters.length === 0 ? (
              <p className="py-8 text-center text-sm text-slate-600">
                No disasters declared yet.
              </p>
            ) : (
              <ul className="space-y-2">
                {disasters.map((disaster) => (
                  <DisasterListRow key={disaster.public_uuid} disaster={disaster} />
                ))}
              </ul>
            )}
          </div>
        </section>

        <section
          aria-labelledby="resource-readiness-heading"
          className="flex min-h-0 min-w-0 flex-col rounded-xl border border-slate-200/80 bg-white shadow-sm"
        >
          <div className="shrink-0 border-b border-slate-100 px-3 py-2.5 lg:px-4">
            <h3
              id="resource-readiness-heading"
              className="text-sm font-semibold text-slate-900"
            >
              Resource Readiness
            </h3>
            <p className="mt-0.5 text-xs text-slate-600">
              Permanent facility registry counts (not per-disaster activations).
            </p>
          </div>
          <div className="p-3 lg:p-4">
            {isLoading && facilities.length === 0 ? (
              <LoadingSkeleton lines={4} />
            ) : (
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-2">
                <ReadinessStat label="Total facilities" value={readiness.total} />
                <ReadinessStat
                  label="Shelter-capable"
                  value={readiness.shelterCapable}
                />
                <ReadinessStat
                  label="Relief hubs / warehouses"
                  value={readiness.reliefHubs}
                />
                <ReadinessStat
                  label="Hospitals / support"
                  value={readiness.hospitalsSupport}
                />
                <ReadinessStat label="Inactive" value={readiness.inactive} />
              </div>
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
