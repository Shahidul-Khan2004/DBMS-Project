"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import type { IncidentCardLocationState } from "@/components/dispatcher/incidents/types";
import {
  getIncidentDisplayLocationFromDetail,
  getLocationSourceReportUuid,
  mapOperationsIncidentDetailResponse,
} from "@/lib/map-incident-command";
import { getOperationsIncident } from "@/lib/operations-incident-api";
import {
  formatSourceIntakeLocationText,
  mapIntakeLocationToIncidentLocation,
} from "@/lib/operations-incident-format";
import { fetchIntakeReportDetail } from "@/lib/operations-intake-triage";

const HYDRATION_CONCURRENCY = 4;

async function hydrateIncidentCardLocation(
  incidentPublicUuid: string,
): Promise<IncidentCardLocationState> {
  const response = await getOperationsIncident(incidentPublicUuid);
  const detail = mapOperationsIncidentDetailResponse(response);
  const { addressText, location } = getIncidentDisplayLocationFromDetail(detail);

  if (addressText && location) {
    return { status: "loaded", address: addressText, location };
  }

  const sourceReportUuid = getLocationSourceReportUuid(detail);
  if (!sourceReportUuid) {
    return { status: "empty" };
  }

  const intakeReport = await fetchIntakeReportDetail(sourceReportUuid);
  const address = formatSourceIntakeLocationText(intakeReport)?.trim();

  if (!address) {
    return { status: "empty" };
  }

  const fallbackLocation =
    location ?? mapIntakeLocationToIncidentLocation(intakeReport.location);
  if (!fallbackLocation) {
    return { status: "empty" };
  }

  return { status: "loaded", address, location: fallbackLocation };
}

async function hydrateWithConcurrency(
  uuids: string[],
  concurrency: number,
  onResult: (uuid: string, state: IncidentCardLocationState) => void,
  isCancelled: () => boolean,
): Promise<void> {
  let index = 0;

  async function worker() {
    while (index < uuids.length) {
      if (isCancelled()) return;

      const currentIndex = index;
      index += 1;
      const uuid = uuids[currentIndex];

      try {
        const state = await hydrateIncidentCardLocation(uuid);
        if (!isCancelled()) {
          onResult(uuid, state);
        }
      } catch {
        if (!isCancelled()) {
          onResult(uuid, { status: "error" });
        }
      }
    }
  }

  const workerCount = Math.min(concurrency, uuids.length);
  await Promise.allSettled(
    Array.from({ length: workerCount }, () => worker()),
  );
}

export function useActiveIncidentCardLocations(incidentPublicUuids: string[]) {
  const cacheRef = useRef<Record<string, IncidentCardLocationState>>({});
  const [cacheVersion, setCacheVersion] = useState(0);
  const [hydrationEpoch, setHydrationEpoch] = useState(0);

  const bumpCache = useCallback(() => {
    setCacheVersion((version) => version + 1);
  }, []);

  const resetCardLocations = useCallback(() => {
    cacheRef.current = {};
    setHydrationEpoch((epoch) => epoch + 1);
    bumpCache();
  }, [bumpCache]);

  const getCardLocation = useCallback(
    (publicUuid: string): IncidentCardLocationState => {
      void cacheVersion;
      return cacheRef.current[publicUuid] ?? { status: "idle" };
    },
    [cacheVersion],
  );

  const setCardLocation = useCallback(
    (publicUuid: string, state: IncidentCardLocationState) => {
      cacheRef.current[publicUuid] = state;
      bumpCache();
    },
    [bumpCache],
  );

  useEffect(() => {
    const uniqueUuids = [...new Set(incidentPublicUuids.filter(Boolean))];
    const pendingUuids = uniqueUuids.filter((uuid) => {
      const existing = cacheRef.current[uuid];
      return !existing || existing.status === "idle";
    });

    if (pendingUuids.length === 0) {
      return;
    }

    for (const uuid of pendingUuids) {
      cacheRef.current[uuid] = { status: "loading" };
    }
    bumpCache();

    let cancelled = false;

    void hydrateWithConcurrency(
      pendingUuids,
      HYDRATION_CONCURRENCY,
      (uuid, state) => setCardLocation(uuid, state),
      () => cancelled,
    );

    return () => {
      cancelled = true;
    };
  }, [incidentPublicUuids, hydrationEpoch, bumpCache, setCardLocation]);

  return { getCardLocation, resetCardLocations };
}
