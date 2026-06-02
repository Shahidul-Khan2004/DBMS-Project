"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { filterNonTerminalOperationsIncidents } from "@/components/dispatcher/incidents/filterNonTerminalOperationsIncidents";
import { mapGateway999IncidentOption } from "@/components/dispatcher/gateway-999/mapGateway999IncidentOption";
import type {
  Gateway999FormState,
  Gateway999Handoff,
  Gateway999IncidentOption,
  Gateway999RouteChoice,
  Gateway999SubmitLabel,
} from "@/components/dispatcher/gateway-999/types";
import type { SelectedIncidentLocation } from "@/components/dispatcher/incidents/create/types";
import type { RouteMode } from "@/components/dispatcher/triage/types";
import { getValidReportedCoordinates } from "@/components/dispatcher/triage/reportedLocationCoords";
import {
  getCurrentBangladeshDatetimeLocal,
  isValidBangladeshLocalDatetime,
  toBangladeshIsoDatetime,
} from "@/lib/datetime";
import {
  mapGateway999Error,
  mapGateway999Handoff,
  submitGateway999Intake,
  type Gateway999Payload,
} from "@/lib/gateway-999-api";
import { getOperationsIncidents } from "@/lib/operations-intake-triage";

function createInitialFormState(): Gateway999FormState {
  return {
    callerPhoneNumber: "",
    callStartedAt: getCurrentBangladeshDatetimeLocal(),
    reportedAt: getCurrentBangladeshDatetimeLocal(),
    categoryCode: "",
    summary: "",
    description: "",
    routeMode: "options",
    severityCode: "",
    incidentTitle: "",
    incidentDescription: "",
    incidentPublicUuid: "",
    linkType: "supporting_report",
    linkNote: "",
    priorityLevel: "",
    selectedLocation: null,
    addressText: "",
    placeName: "",
  };
}

function isRouteChoice(mode: RouteMode): mode is Gateway999RouteChoice {
  return (
    mode === "service_case" ||
    mode === "emergency_incident" ||
    mode === "existing_incident"
  );
}

function getSubmitLabel(routeMode: RouteMode): Gateway999SubmitLabel {
  switch (routeMode) {
    case "emergency_incident":
      return "Create Emergency Incident";
    case "existing_incident":
      return "Link Call to Existing Incident";
    case "service_case":
      return "Create Service Case";
    default:
      return "Select Route to Continue";
  }
}

export function useGateway999Intake() {
  const [form, setForm] = useState<Gateway999FormState>(createInitialFormState);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState("");
  const [showValidation, setShowValidation] = useState(false);
  const [handoff, setHandoff] = useState<Gateway999Handoff | null>(null);

  const [incidents, setIncidents] = useState<Gateway999IncidentOption[]>([]);
  const [incidentsLoading, setIncidentsLoading] = useState(false);
  const [incidentsError, setIncidentsError] = useState<string | null>(null);

  const validLocationCoords = useMemo(
    () =>
      form.selectedLocation
        ? getValidReportedCoordinates(
            form.selectedLocation.latitude,
            form.selectedLocation.longitude,
          )
        : null,
    [form.selectedLocation],
  );

  const loadIncidents = useCallback(async () => {
    setIncidentsLoading(true);
    setIncidentsError(null);

    try {
      const data = await getOperationsIncidents({ limit: 50, offset: 0 });
      const mapped = filterNonTerminalOperationsIncidents(data.incidents)
        .map(mapGateway999IncidentOption)
        .filter((entry): entry is NonNullable<typeof entry> => entry != null);
      setIncidents(mapped);
    } catch (err) {
      setIncidentsError(mapGateway999Error(err, "Could not load active incidents."));
      setIncidents([]);
    } finally {
      setIncidentsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (form.routeMode === "existing_incident" && !handoff) {
      void loadIncidents();
    }
  }, [form.routeMode, handoff, loadIncidents]);

  const updateForm = useCallback((patch: Partial<Gateway999FormState>) => {
    setForm((current) => ({ ...current, ...patch }));
    setSubmitError("");
  }, []);

  const handleSelectRoute = useCallback((mode: Gateway999RouteChoice) => {
    setForm((current) => ({
      ...current,
      routeMode: mode,
      severityCode: mode === "emergency_incident" ? current.severityCode : "",
      incidentTitle: mode === "emergency_incident" ? current.incidentTitle : "",
      incidentDescription:
        mode === "emergency_incident" ? current.incidentDescription : "",
      incidentPublicUuid:
        mode === "existing_incident" ? current.incidentPublicUuid : "",
      linkType: mode === "existing_incident" ? current.linkType : "supporting_report",
      linkNote: mode === "existing_incident" ? current.linkNote : "",
      priorityLevel: mode === "service_case" ? current.priorityLevel : "",
    }));
    setSubmitError("");
    setShowValidation(false);
  }, []);

  const handleLocationChange = useCallback(
    (location: SelectedIncidentLocation | null) => {
      updateForm({
        selectedLocation: location,
        ...(location
          ? {}
          : {
              addressText: "",
              placeName: "",
            }),
      });
    },
    [updateForm],
  );

  const handleAddressTextChange = useCallback(
    (value: string) => {
      setForm((current) => ({
        ...current,
        addressText: value,
        selectedLocation: current.selectedLocation
          ? { ...current.selectedLocation, addressText: value.trim() || undefined }
          : current.selectedLocation,
      }));
      setSubmitError("");
    },
    [],
  );

  const handlePlaceNameChange = useCallback((value: string) => {
    setForm((current) => ({
      ...current,
      placeName: value,
      selectedLocation: current.selectedLocation
        ? { ...current.selectedLocation, placeName: value.trim() || undefined }
        : current.selectedLocation,
    }));
    setSubmitError("");
  }, []);

  const resetForm = useCallback(() => {
    setForm(createInitialFormState());
    setSubmitError("");
    setShowValidation(false);
    setHandoff(null);
    setIncidents([]);
    setIncidentsError(null);
  }, []);

  const buildPayload = useCallback((): Gateway999Payload | null => {
    const categoryCode = form.categoryCode.trim();
    const summary = form.summary.trim();
    const description = form.description.trim();

    if (!categoryCode) {
      setSubmitError("Choose a category for this call.");
      return null;
    }

    if (!summary) {
      setSubmitError("Add a summary for this call.");
      return null;
    }

    if (!isRouteChoice(form.routeMode)) {
      setSubmitError("Select a route before submitting.");
      return null;
    }

    if (!validLocationCoords) {
      setSubmitError("Select a reported location before submitting.");
      return null;
    }

    if (form.callStartedAt && !isValidBangladeshLocalDatetime(form.callStartedAt)) {
      setSubmitError("Call started time must be a valid Bangladesh date and time.");
      return null;
    }

    if (form.reportedAt && !isValidBangladeshLocalDatetime(form.reportedAt)) {
      setSubmitError("Reported time must be a valid Bangladesh date and time.");
      return null;
    }

    const manualAddress = form.addressText.trim();
    const manualPlace = form.placeName.trim();
    const pickerAddress = form.selectedLocation?.addressText?.trim() ?? "";
    const pickerPlace = form.selectedLocation?.placeName?.trim() ?? "";

    const resolvedAddress =
      manualAddress || pickerAddress || "Selected map point";
    const resolvedPlace = manualPlace || pickerPlace || undefined;

    if (resolvedAddress.length > 255) {
      setSubmitError("Location address must be 255 characters or fewer.");
      return null;
    }

    if (resolvedPlace && resolvedPlace.length > 150) {
      setSubmitError("Place name must be 150 characters or fewer.");
      return null;
    }

    const payload: Gateway999Payload = {
      disposition: form.routeMode,
      categoryCode,
      summary,
      location: {
        latitude: validLocationCoords.latitude,
        longitude: validLocationCoords.longitude,
        address_text: resolvedAddress,
        place_name: resolvedPlace,
        source: "dispatcher_selected",
      },
    };

    if (description) {
      payload.description = description;
    }

    const callerPhone = form.callerPhoneNumber.trim();
    if (callerPhone) {
      payload.callerPhoneNumber = callerPhone;
    }

    if (form.callStartedAt) {
      payload.callStartedAt = toBangladeshIsoDatetime(form.callStartedAt);
    }

    if (form.reportedAt) {
      payload.reportedAt = toBangladeshIsoDatetime(form.reportedAt);
    }

    if (form.routeMode === "emergency_incident") {
      if (!form.severityCode) {
        setSubmitError("Choose a severity level for the emergency incident.");
        return null;
      }

      payload.severityCode = form.severityCode;

      const incidentTitle = form.incidentTitle.trim();
      const incidentDescription = form.incidentDescription.trim();
      if (incidentTitle) payload.incidentTitle = incidentTitle;
      if (incidentDescription) payload.incidentDescription = incidentDescription;
    }

    if (form.routeMode === "existing_incident") {
      if (!form.incidentPublicUuid) {
        setSubmitError("Select an active incident to link this call.");
        return null;
      }

      payload.incidentPublicUuid = form.incidentPublicUuid;
      payload.linkType = form.linkType;

      const note = form.linkNote.trim();
      if (note) payload.note = note;
    }

    if (form.routeMode === "service_case" && form.priorityLevel) {
      payload.priorityLevel = form.priorityLevel;
    }

    return payload;
  }, [form, validLocationCoords]);

  const canSubmit = useMemo(() => {
    if (isSubmitting || handoff) return false;
    if (!form.categoryCode.trim() || !form.summary.trim()) return false;
    if (!isRouteChoice(form.routeMode)) return false;
    if (!validLocationCoords) return false;

    if (form.routeMode === "emergency_incident" && !form.severityCode) {
      return false;
    }

    if (form.routeMode === "existing_incident" && !form.incidentPublicUuid) {
      return false;
    }

    return true;
  }, [form, handoff, isSubmitting, validLocationCoords]);

  const submitLabel = getSubmitLabel(form.routeMode);

  const handleSubmit = useCallback(
    async (event: FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      setSubmitError("");
      setShowValidation(true);

      if (isSubmitting || handoff) return;

      const payload = buildPayload();
      if (!payload) return;

      setIsSubmitting(true);

      try {
        const response = await submitGateway999Intake(payload);
        const nextHandoff = mapGateway999Handoff(
          response,
          payload.disposition,
          payload.summary,
          payload.disposition === "existing_incident"
            ? form.incidentPublicUuid
            : undefined,
        );
        setHandoff(nextHandoff);
      } catch (err) {
        setSubmitError(mapGateway999Error(err));
      } finally {
        setIsSubmitting(false);
      }
    },
    [buildPayload, form.incidentPublicUuid, handoff, isSubmitting],
  );

  return {
    form,
    updateForm,
    handleSelectRoute,
    handleLocationChange,
    handleAddressTextChange,
    handlePlaceNameChange,
    handleSubmit,
    resetForm,
    isSubmitting,
    submitError,
    showValidation,
    handoff,
    validLocationCoords,
    canSubmit,
    submitLabel,
    incidents,
    incidentsLoading,
    incidentsError,
    loadIncidents,
  };
}
