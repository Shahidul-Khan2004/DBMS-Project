"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { getDisasterDashboard } from "@/lib/disaster-operations-api";
import { isTerminalDisasterStatus } from "@/lib/disaster-operations-format";
import { listAdminFacilities } from "@/lib/admin-facility-api";
import type { DisasterDashboardResponse } from "@/types/disaster-operations";
import type { AdminFacilityListItem, FacilityLocation } from "@/types/admin-facility";

export function useDisasterDashboard(disasterPublicUuid: string) {
  const [dashboard, setDashboard] = useState<DisasterDashboardResponse | null>(
    null,
  );
  const [facilityLocations, setFacilityLocations] = useState<
    Map<string, FacilityLocation | null | undefined>
  >(new Map());
  const [facilities, setFacilities] = useState<AdminFacilityListItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadFacilities = useCallback(async () => {
    try {
      const data = await listAdminFacilities();
      const map = new Map<string, FacilityLocation | null | undefined>();
      for (const facility of data.facilities) {
        map.set(facility.publicUuid, facility.location);
      }
      setFacilityLocations(map);
      setFacilities(data.facilities ?? []);
    } catch {
      setFacilityLocations(new Map());
      setFacilities([]);
    }
  }, []);

  const refresh = useCallback(async () => {
    setIsRefreshing(true);
    setError(null);
    try {
      const data = await getDisasterDashboard(disasterPublicUuid);
      setDashboard(data);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load disaster dashboard.",
      );
    } finally {
      setIsRefreshing(false);
    }
  }, [disasterPublicUuid]);

  const load = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [data] = await Promise.all([
        getDisasterDashboard(disasterPublicUuid),
        loadFacilities(),
      ]);
      setDashboard(data);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load disaster dashboard.",
      );
      setDashboard(null);
    } finally {
      setIsLoading(false);
    }
  }, [disasterPublicUuid, loadFacilities]);

  useEffect(() => {
    void load();
  }, [load]);

  const isReadOnly = useMemo(
    () => isTerminalDisasterStatus(dashboard?.disaster.status_code),
    [dashboard?.disaster.status_code],
  );

  return {
    dashboard,
    facilities,
    facilityLocations,
    isLoading,
    isRefreshing,
    error,
    isReadOnly,
    refresh,
    reload: load,
  };
}
