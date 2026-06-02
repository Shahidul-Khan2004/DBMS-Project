"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { ApiError } from "@/lib/api";
import {
  getAgencyDispatches,
  getAgencyIncidentNotes,
  getAgencyIncidentResponseLogs,
  getAgencyIncidents,
  getAgencyMe,
  getAgencyUnits,
} from "@/lib/agency-api";
import { mapAgencyAccessError, mapAgencyIncidentError } from "@/lib/agency-api-errors";
import {
  groupDispatchesByIncident,
  selectDefaultIncidentUuid,
} from "@/lib/agency-incident-utils";
import type { GroupedAgencyIncident } from "@/lib/agency-incident-utils";
import type {
  AgencyDispatch,
  AgencyDispatchStatusAction,
  AgencyIncident,
  AgencyMeResponse,
  AgencyNote,
  AgencyResponseLog,
  AgencyUnit,
} from "@/types/agency";

const LIST_LIMIT = 100;

export function useAgencyCommandCenter() {
  const [me, setMe] = useState<AgencyMeResponse | null>(null);
  const [incidents, setIncidents] = useState<AgencyIncident[]>([]);
  const [dispatches, setDispatches] = useState<AgencyDispatch[]>([]);
  const [units, setUnits] = useState<AgencyUnit[]>([]);
  const [selectedIncidentUuid, setSelectedIncidentUuid] = useState<string | null>(null);
  const [responseLogs, setResponseLogs] = useState<AgencyResponseLog[]>([]);
  const [notes, setNotes] = useState<AgencyNote[]>([]);

  const [meLoading, setMeLoading] = useState(true);
  const [dispatchesLoading, setDispatchesLoading] = useState(true);
  const [unitsLoading, setUnitsLoading] = useState(true);
  const [logsLoading, setLogsLoading] = useState(false);
  const [notesLoading, setNotesLoading] = useState(false);

  const [accessError, setAccessError] = useState<string | null>(null);
  const [dispatchesError, setDispatchesError] = useState<string | null>(null);
  const [unitsError, setUnitsError] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const [statusModal, setStatusModal] = useState<{
    dispatch: AgencyDispatch;
    action: AgencyDispatchStatusAction;
  } | null>(null);

  const groupedIncidents = useMemo(
    () => groupDispatchesByIncident(dispatches, incidents),
    [dispatches, incidents],
  );

  const selectedIncident = useMemo(
    () =>
      groupedIncidents.find((i) => i.incidentPublicUuid === selectedIncidentUuid) ??
      null,
    [groupedIncidents, selectedIncidentUuid],
  );

  const loadMe = useCallback(async () => {
    try {
      const data = await getAgencyMe();
      setMe(data);
      setAccessError(null);
      return data;
    } catch (err) {
      setMe(null);
      setAccessError(mapAgencyAccessError(err));
      throw err;
    }
  }, []);

  const loadIncidents = useCallback(async () => {
    try {
      const data = await getAgencyIncidents({ limit: LIST_LIMIT, offset: 0 });
      const items = data.incidents ?? [];
      setIncidents(items);
      return items;
    } catch {
      setIncidents([]);
      return [];
    }
  }, []);

  const loadDispatches = useCallback(async () => {
    try {
      const data = await getAgencyDispatches({ limit: LIST_LIMIT, offset: 0 });
      const items = data.dispatches ?? [];
      setDispatches(items);
      setDispatchesError(null);
      return items;
    } catch (err) {
      setDispatches([]);
      if (err instanceof ApiError && (err.status === 403 || err.status === 401)) {
        setAccessError(mapAgencyAccessError(err));
      } else {
        setDispatchesError("Unable to load dispatches. Please try again.");
      }
      return [];
    }
  }, []);

  const loadUnits = useCallback(async () => {
    try {
      const data = await getAgencyUnits({ limit: LIST_LIMIT, offset: 0 });
      const items = data.units ?? [];
      setUnits(items);
      setUnitsError(null);
      return items;
    } catch (err) {
      setUnits([]);
      if (err instanceof ApiError && (err.status === 403 || err.status === 401)) {
        setAccessError(mapAgencyAccessError(err));
      } else {
        setUnitsError("Unable to load units. Please try again.");
      }
      return [];
    }
  }, []);

  const loadIncidentDetails = useCallback(async (incidentPublicUuid: string) => {
    setLogsLoading(true);
    setNotesLoading(true);
    try {
      const [logsRes, notesRes] = await Promise.all([
        getAgencyIncidentResponseLogs(incidentPublicUuid, { limit: LIST_LIMIT }),
        getAgencyIncidentNotes(incidentPublicUuid, { limit: LIST_LIMIT }),
      ]);
      setResponseLogs(logsRes.response_logs ?? []);
      setNotes(notesRes.notes ?? []);
    } catch (err) {
      setResponseLogs([]);
      setNotes([]);
      if (process.env.NODE_ENV === "development") {
        console.error("Failed to load incident details", err);
      }
      mapAgencyIncidentError(err);
    } finally {
      setLogsLoading(false);
      setNotesLoading(false);
    }
  }, []);

  const refreshAll = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const [, dispatchItems, incidentItems] = await Promise.all([
        loadMe(),
        loadDispatches(),
        loadIncidents(),
        loadUnits(),
      ]);
      const grouped = groupDispatchesByIncident(dispatchItems, incidentItems);
      if (selectedIncidentUuid) {
        const stillExists = grouped.some(
          (i) => i.incidentPublicUuid === selectedIncidentUuid,
        );
        if (!stillExists) {
          setSelectedIncidentUuid(selectDefaultIncidentUuid(grouped));
        }
      }
    } finally {
      setIsRefreshing(false);
    }
  }, [loadMe, loadDispatches, loadIncidents, loadUnits, selectedIncidentUuid]);

  useEffect(() => {
    let cancelled = false;

    async function init() {
      setMeLoading(true);
      setDispatchesLoading(true);
      setUnitsLoading(true);
      try {
        const [, dispatchItems, incidentItems] = await Promise.all([
          loadMe(),
          loadDispatches(),
          loadIncidents(),
          loadUnits(),
        ]);
        if (cancelled) return;
        const grouped = groupDispatchesByIncident(dispatchItems, incidentItems);
        setSelectedIncidentUuid(
          (current) => current ?? selectDefaultIncidentUuid(grouped),
        );
      } catch {
        // access error handled in loadMe
      } finally {
        if (!cancelled) {
          setMeLoading(false);
          setDispatchesLoading(false);
          setUnitsLoading(false);
        }
      }
    }

    void init();

    return () => {
      cancelled = true;
    };
  }, [loadMe, loadDispatches, loadIncidents, loadUnits]);

  useEffect(() => {
    if (!selectedIncidentUuid) {
      setResponseLogs([]);
      setNotes([]);
      return;
    }
    void loadIncidentDetails(selectedIncidentUuid);
  }, [selectedIncidentUuid, loadIncidentDetails]);

  const handleDispatchStatusSuccess = useCallback(async () => {
    const [dispatchItems, incidentItems] = await Promise.all([
      loadDispatches(),
      loadIncidents(),
    ]);
    await loadMe();
    const grouped = groupDispatchesByIncident(dispatchItems, incidentItems);
    if (selectedIncidentUuid) {
      const stillExists = grouped.some(
        (i) => i.incidentPublicUuid === selectedIncidentUuid,
      );
      if (!stillExists) {
        setSelectedIncidentUuid(selectDefaultIncidentUuid(grouped));
      }
    }
  }, [loadDispatches, loadMe, loadIncidents, selectedIncidentUuid]);

  const openStatusAction = useCallback(
    (dispatch: AgencyDispatch, action: AgencyDispatchStatusAction) => {
      setStatusModal({ dispatch, action });
    },
    [],
  );

  const refreshLogs = useCallback(async () => {
    if (!selectedIncidentUuid) return;
    await loadIncidentDetails(selectedIncidentUuid);
  }, [selectedIncidentUuid, loadIncidentDetails]);

  const refreshUnitsAndCounts = useCallback(async () => {
    await Promise.all([loadUnits(), loadMe(), loadDispatches(), loadIncidents()]);
  }, [loadUnits, loadMe, loadDispatches, loadIncidents]);

  return {
    me,
    groupedIncidents,
    selectedIncident,
    selectedIncidentUuid,
    setSelectedIncidentUuid,
    units,
    responseLogs,
    notes,
    meLoading,
    dispatchesLoading,
    unitsLoading,
    logsLoading,
    notesLoading,
    accessError,
    dispatchesError,
    unitsError,
    isRefreshing,
    statusModal,
    setStatusModal,
    refreshAll,
    openStatusAction,
    handleDispatchStatusSuccess,
    refreshLogs,
    refreshUnitsAndCounts,
  };
}

export type { GroupedAgencyIncident };
