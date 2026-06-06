"use client";

import { useCallback, useEffect, useState } from "react";
import { ApiError } from "@/lib/api";
import {
  getAgencyDisasterDetail,
  getAgencyDisasterIncidents,
} from "@/lib/agency-disaster-api";
import type {
  AgencyDisasterDetailResponse,
  AgencyDisasterIncidentsResponse,
} from "@/types/agency-disaster";

export function useAgencyDisasterDetail(disasterPublicUuid: string | null) {
  const [detail, setDetail] = useState<AgencyDisasterDetailResponse | null>(null);
  const [incidents, setIncidents] = useState<AgencyDisasterIncidentsResponse | null>(
    null,
  );
  const [loading, setLoading] = useState(true);
  const [incidentsLoading, setIncidentsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadDetail = useCallback(async () => {
    if (!disasterPublicUuid) return;
    setLoading(true);
    setError(null);
    try {
      const data = await getAgencyDisasterDetail(disasterPublicUuid);
      setDetail(data);
    } catch (err) {
      setDetail(null);
      if (err instanceof ApiError && err.status === 404) {
        setError("This disaster is not assigned to your agency.");
      } else {
        setError("Unable to load disaster details. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  }, [disasterPublicUuid]);

  const loadIncidents = useCallback(async () => {
    if (!disasterPublicUuid) return;
    setIncidentsLoading(true);
    try {
      const data = await getAgencyDisasterIncidents(disasterPublicUuid);
      setIncidents(data);
    } catch {
      setIncidents({ disaster_public_uuid: disasterPublicUuid, incidents: [] });
    } finally {
      setIncidentsLoading(false);
    }
  }, [disasterPublicUuid]);

  const refreshAll = useCallback(async () => {
    await Promise.all([loadDetail(), loadIncidents()]);
  }, [loadDetail, loadIncidents]);

  useEffect(() => {
    void loadDetail();
  }, [loadDetail]);

  useEffect(() => {
    void loadIncidents();
  }, [loadIncidents]);

  return {
    detail,
    incidents,
    loading,
    incidentsLoading,
    error,
    refreshAll,
    loadDetail,
  };
}
