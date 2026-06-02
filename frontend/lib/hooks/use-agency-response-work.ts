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

export function useAgencyResponseWork() {
  const [me, setMe] = useState<AgencyMeResponse | null>(null);
  const [incidents, setIncidents] = useState<AgencyIncident[]>([]);
  const [dispatches, setDispatches] = useState<AgencyDispatch[]>([]);
  const [units, setUnits] = useState<AgencyUnit[]>([]);
  const [selectedIncidentUuid, setSelectedIncidentUuid] = useState<string | null>(null);
  const [responseLogs, setResponseLogs] = useState<AgencyResponseLog[]>([]);
  const [notes, setNotes] = useState<AgencyNote[]>([]);

  const [loading, setLoading] = useState(true);
  const [logsLoading, setLogsLoading] = useState(false);
  const [notesLoading, setNotesLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [accessError, setAccessError] = useState<string | null>(null);

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

  const loadCore = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [meRes, incidentsRes, dispatchesRes, unitsRes] = await Promise.all([
        getAgencyMe(),
        getAgencyIncidents({ limit: LIST_LIMIT }),
        getAgencyDispatches({ limit: LIST_LIMIT }),
        getAgencyUnits({ limit: LIST_LIMIT }),
      ]);
      setMe(meRes);
      setAccessError(null);
      const incidentItems = incidentsRes.incidents ?? [];
      const dispatchItems = dispatchesRes.dispatches ?? [];
      setIncidents(incidentItems);
      setDispatches(dispatchItems);
      setUnits(unitsRes.units ?? []);
      const grouped = groupDispatchesByIncident(dispatchItems, incidentItems);
      setSelectedIncidentUuid(
        (current) => current ?? selectDefaultIncidentUuid(grouped),
      );
    } catch (err) {
      if (err instanceof ApiError && (err.status === 403 || err.status === 401)) {
        setAccessError(mapAgencyAccessError(err));
      } else {
        setError("Unable to load response work. Please try again.");
      }
    } finally {
      setLoading(false);
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
      mapAgencyIncidentError(err);
    } finally {
      setLogsLoading(false);
      setNotesLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadCore();
  }, [loadCore]);

  useEffect(() => {
    if (!selectedIncidentUuid) {
      setResponseLogs([]);
      setNotes([]);
      return;
    }
    void loadIncidentDetails(selectedIncidentUuid);
  }, [selectedIncidentUuid, loadIncidentDetails]);

  const handleDispatchStatusSuccess = useCallback(async () => {
    const [meRes, incidentsRes, dispatchesRes] = await Promise.all([
      getAgencyMe(),
      getAgencyIncidents({ limit: LIST_LIMIT }),
      getAgencyDispatches({ limit: LIST_LIMIT }),
    ]);
    setMe(meRes);
    const incidentItems = incidentsRes.incidents ?? [];
    const dispatchItems = dispatchesRes.dispatches ?? [];
    setIncidents(incidentItems);
    setDispatches(dispatchItems);
    const grouped = groupDispatchesByIncident(dispatchItems, incidentItems);
    if (
      selectedIncidentUuid &&
      !grouped.some((i) => i.incidentPublicUuid === selectedIncidentUuid)
    ) {
      setSelectedIncidentUuid(selectDefaultIncidentUuid(grouped));
    }
  }, [selectedIncidentUuid]);

  const refreshLogs = useCallback(async () => {
    if (!selectedIncidentUuid) return;
    await loadIncidentDetails(selectedIncidentUuid);
  }, [selectedIncidentUuid, loadIncidentDetails]);

  return {
    me,
    units,
    groupedIncidents,
    selectedIncident,
    selectedIncidentUuid,
    setSelectedIncidentUuid,
    responseLogs,
    notes,
    loading,
    logsLoading,
    notesLoading,
    error,
    accessError,
    statusModal,
    setStatusModal,
    loadCore,
    handleDispatchStatusSuccess,
    refreshLogs,
    openStatusAction: (
      dispatch: AgencyDispatch,
      action: AgencyDispatchStatusAction,
    ) => setStatusModal({ dispatch, action }),
  };
}

export type { GroupedAgencyIncident };
