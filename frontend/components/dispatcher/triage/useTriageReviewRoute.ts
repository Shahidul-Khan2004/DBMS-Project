"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";
import {
  createEmergencyDraft,
  createLinkDraft,
  createServiceCaseDraft,
} from "@/components/dispatcher/triage/draftDefaults";
import { mapOperationsIntakeToQueueItem } from "@/components/dispatcher/triage/mapOperationsIntake";
import { hasValidReportedLocation } from "@/components/dispatcher/triage/reportedLocationCoords";
import {
  isSuccessRouteMode,
  mapIncidentToOption,
  parseEmergencySeverity,
  parseServiceCasePriority,
  resetDraftsForItem,
  type RouteChoice,
} from "@/components/dispatcher/triage/triageReviewRouteUtils";
import type {
  ActiveIncidentOption,
  DismissDraft,
  EmergencyDraft,
  IntakeQueueItem,
  LinkDraft,
  RouteMode,
  RouteResult,
  ServiceCaseDraft,
} from "@/components/dispatcher/triage/types";
import { tryLinkIncidentToDisaster } from "@/lib/disaster-incident-link";
import {
  classifyIntakeAsServiceCase,
  dismissIntakeReport,
  fetchIntakeReportDetail,
  getOperationsIncidents,
  linkIntakeToIncident,
  mapApiErrorToRouteMessage,
  mapApiErrorToTriageMessage,
  promoteIntakeToEmergencyIncident,
} from "@/lib/operations-intake-triage";
import { fetchIntakeReporterRisk } from "@/lib/reporter-risk-api";
import type { ReporterRiskSummary } from "@/types/reporter-risk";

export type UseTriageReviewRouteOptions = {
  reportId: string | null;
  enabled: boolean;
  onAfterRouteSuccess?: () => void | Promise<void>;
  onAfterLocationUpdate?: () => void | Promise<void>;
};

export function useTriageReviewRoute({
  reportId,
  enabled,
  onAfterRouteSuccess,
  onAfterLocationUpdate,
}: UseTriageReviewRouteOptions) {
  const router = useRouter();
  const [selectedDetail, setSelectedDetail] = useState<IntakeQueueItem | null>(
    null,
  );
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [routeMode, setRouteMode] = useState<RouteMode>("options");
  const [serviceCaseDraft, setServiceCaseDraft] = useState<ServiceCaseDraft>({
    title: "",
    description: "",
    priority: "medium",
  });
  const [emergencyDraft, setEmergencyDraft] = useState<EmergencyDraft>({
    severity: "high",
    title: "",
    description: "",
  });
  const [linkDraft, setLinkDraft] = useState<LinkDraft>(() => createLinkDraft());
  const [dismissDraft, setDismissDraft] = useState<DismissDraft>({ note: "" });
  const [routeResult, setRouteResult] = useState<RouteResult | null>(null);
  const [handoffItem, setHandoffItem] = useState<IntakeQueueItem | null>(null);
  const [routeError, setRouteError] = useState<string | null>(null);
  const [submittingRoute, setSubmittingRoute] = useState<
    "service_case" | "emergency" | "link" | "duplicate" | "false_report" | null
  >(null);
  const [activeIncidents, setActiveIncidents] = useState<ActiveIncidentOption[]>(
    [],
  );
  const [incidentsLoading, setIncidentsLoading] = useState(false);
  const [incidentsError, setIncidentsError] = useState<string | null>(null);
  const [locationDialogOpen, setLocationDialogOpen] = useState(false);
  const [historyDialogOpen, setHistoryDialogOpen] = useState(false);
  const [selectedDisasterPublicUuid, setSelectedDisasterPublicUuid] = useState<
    string | null
  >(null);
  const [reporterRisk, setReporterRisk] = useState<ReporterRiskSummary | null>(
    null,
  );
  const [reporterRiskLoading, setReporterRiskLoading] = useState(false);
  const [verificationModalOpen, setVerificationModalOpen] = useState(false);

  const clearRouteMutationState = useCallback(() => {
    setRouteError(null);
    setRouteResult(null);
    setHandoffItem(null);
  }, []);

  const applyDraftsForItem = useCallback((item: IntakeQueueItem) => {
    const drafts = resetDraftsForItem(item);
    setServiceCaseDraft(drafts.serviceCaseDraft);
    setEmergencyDraft(drafts.emergencyDraft);
    setLinkDraft(drafts.linkDraft);
  }, []);

  const resetWorkflowState = useCallback(() => {
    setRouteMode("options");
    clearRouteMutationState();
    setSelectedDetail(null);
    setDetailError(null);
    setDetailLoading(false);
    setServiceCaseDraft({ title: "", description: "", priority: "medium" });
    setEmergencyDraft({ severity: "high", title: "", description: "" });
    setLinkDraft(createLinkDraft());
    setDismissDraft({ note: "" });
    setActiveIncidents([]);
    setIncidentsError(null);
    setLocationDialogOpen(false);
    setHistoryDialogOpen(false);
    setSelectedDisasterPublicUuid(null);
    setReporterRisk(null);
    setReporterRiskLoading(false);
    setVerificationModalOpen(false);
  }, [clearRouteMutationState]);

  const loadDetail = useCallback(
    async (reportPublicUuid: string) => {
      if (!reportPublicUuid) {
        setSelectedDetail(null);
        setDetailError(null);
        return;
      }

      setDetailLoading(true);
      setDetailError(null);
      setReporterRiskLoading(true);

      try {
        const [report, riskData] = await Promise.all([
          fetchIntakeReportDetail(reportPublicUuid),
          fetchIntakeReporterRisk(reportPublicUuid).catch(() => ({
            reporter_risk: null,
            recent_verifications: [],
          })),
        ]);
        setReporterRisk(riskData.reporter_risk);
        const mapped = mapOperationsIntakeToQueueItem(report);
        if (!mapped) {
          setDetailError("This intake report is no longer pending triage.");
          setSelectedDetail(null);
          return;
        }
        setSelectedDetail(mapped);
        applyDraftsForItem(mapped);
      } catch (err) {
        if (process.env.NODE_ENV === "development") {
          console.error("Failed to load intake detail", err);
        }
        setDetailError(mapApiErrorToTriageMessage(err, "detail"));
        setSelectedDetail(null);
        setReporterRisk(null);
      } finally {
        setDetailLoading(false);
        setReporterRiskLoading(false);
      }
    },
    [applyDraftsForItem],
  );

  const loadActiveIncidents = useCallback(async () => {
    setIncidentsLoading(true);
    setIncidentsError(null);

    try {
      const data = await getOperationsIncidents({ limit: 50, offset: 0 });
      const options = (data.incidents ?? [])
        .map(mapIncidentToOption)
        .filter((entry): entry is ActiveIncidentOption => entry != null);
      setActiveIncidents(options);
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Failed to load active incidents", err);
      }
      setIncidentsError(
        err instanceof Error
          ? err.message
          : "Unable to load active incidents.",
      );
      setActiveIncidents([]);
    } finally {
      setIncidentsLoading(false);
    }
  }, []);

  const refreshAfterLocationUpdate = useCallback(async () => {
    if (!reportId) return;
    await loadDetail(reportId);
    await onAfterLocationUpdate?.();
  }, [loadDetail, onAfterLocationUpdate, reportId]);

  const handleSelectRoute = useCallback(
    (mode: RouteChoice) => {
      if (!selectedDetail) return;
      setRouteError(null);
      setRouteMode(mode);
      if (mode === "service_case") {
        setServiceCaseDraft(createServiceCaseDraft(selectedDetail));
      } else if (mode === "emergency_incident") {
        setEmergencyDraft(createEmergencyDraft(selectedDetail));
      } else if (mode === "existing_incident") {
        setLinkDraft(createLinkDraft());
      } else {
        setDismissDraft({ note: "" });
      }
    },
    [selectedDetail],
  );

  const handleBackToOptions = useCallback(() => {
    setRouteMode("options");
    setRouteError(null);
    setDismissDraft({ note: "" });
    if (selectedDetail) {
      applyDraftsForItem(selectedDetail);
    }
  }, [applyDraftsForItem, selectedDetail]);

  const completeRouteSuccess = useCallback(
    async (nextRouteMode: RouteMode, result: RouteResult) => {
      setHandoffItem(selectedDetail);
      setRouteResult(result);
      setRouteMode(nextRouteMode);
      setRouteError(null);
      await onAfterRouteSuccess?.();
    },
    [onAfterRouteSuccess, selectedDetail],
  );

  const handleSubmitServiceCase = useCallback(async () => {
    if (!selectedDetail || !reportId) return;
    if (!hasValidReportedLocation(selectedDetail.location)) {
      setRouteError(
        "A reported location is required before this report can be routed.",
      );
      return;
    }

    setSubmittingRoute("service_case");
    setRouteError(null);

    try {
      const data = await classifyIntakeAsServiceCase(reportId, {
        title: serviceCaseDraft.title.trim() || undefined,
        description: serviceCaseDraft.description.trim() || undefined,
        priorityLevel: serviceCaseDraft.priority,
      });

      const serviceCase = data.service_case;
      if (!serviceCase?.public_uuid) {
        setRouteError(
          "Service case was created but the response was incomplete. Refresh the queue and try again.",
        );
        return;
      }

      await completeRouteSuccess("success_service_case", {
        kind: "service_case",
        publicUuid: serviceCase.public_uuid,
        caseCode: serviceCase.case_code ?? "",
        title:
          serviceCase.title?.trim() ||
          serviceCaseDraft.title.trim() ||
          selectedDetail.summary,
        priority: parseServiceCasePriority(
          serviceCase.priority_level,
          serviceCaseDraft.priority,
        ),
        statusCode: serviceCase.status_code?.trim() || "submitted",
      });
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Service case classification failed", err);
      }
      setRouteError(mapApiErrorToRouteMessage(err, "service_case"));
    } finally {
      setSubmittingRoute(null);
    }
  }, [
    completeRouteSuccess,
    reportId,
    selectedDetail,
    serviceCaseDraft,
  ]);

  const handleSubmitEmergency = useCallback(async () => {
    if (!selectedDetail || !reportId) return;
    if (!hasValidReportedLocation(selectedDetail.location)) {
      setRouteError(
        "A reported location is required before this report can be routed.",
      );
      return;
    }

    setSubmittingRoute("emergency");
    setRouteError(null);

    try {
      const data = await promoteIntakeToEmergencyIncident(reportId, {
        severityCode: emergencyDraft.severity,
        incidentTitle: emergencyDraft.title.trim() || undefined,
        incidentDescription: emergencyDraft.description.trim() || undefined,
      });

      const incident = data.incident;
      if (!incident?.public_uuid) {
        setRouteError(
          "Emergency incident was created but the response was incomplete. Refresh the queue and try again.",
        );
        return;
      }

      if (selectedDisasterPublicUuid) {
        const linkResult = await tryLinkIncidentToDisaster({
          disasterUuid: selectedDisasterPublicUuid,
          incidentUuid: incident.public_uuid,
        });
        if (!linkResult.ok) {
          toast.warning(linkResult.message);
        }
      }

      await completeRouteSuccess("success_emergency_incident", {
        kind: "emergency_incident",
        publicUuid: incident.public_uuid,
        incidentCode: incident.incident_code ?? "",
        title:
          incident.title?.trim() ||
          emergencyDraft.title.trim() ||
          selectedDetail.summary,
        severity: parseEmergencySeverity(
          incident.severity_code,
          emergencyDraft.severity,
        ),
        statusCode: incident.status_code?.trim() || "reported",
      });
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Emergency promotion failed", err);
      }
      setRouteError(mapApiErrorToRouteMessage(err, "emergency"));
    } finally {
      setSubmittingRoute(null);
    }
  }, [
    completeRouteSuccess,
    emergencyDraft,
    reportId,
    selectedDetail,
    selectedDisasterPublicUuid,
  ]);

  const handleSubmitLink = useCallback(async () => {
    if (!selectedDetail || !reportId) return;
    if (!hasValidReportedLocation(selectedDetail.location)) {
      setRouteError(
        "A reported location is required before this report can be routed.",
      );
      return;
    }
    if (!linkDraft.incidentId) {
      setRouteError("Select an active incident before linking this report.");
      return;
    }

    const selectedIncident = activeIncidents.find(
      (incident) => incident.id === linkDraft.incidentId,
    );

    setSubmittingRoute("link");
    setRouteError(null);

    try {
      await linkIntakeToIncident(linkDraft.incidentId, {
        intakeReportPublicUuid: reportId,
        linkType: linkDraft.linkType,
        note: linkDraft.note.trim() || undefined,
      });

      if (selectedDisasterPublicUuid) {
        const linkResult = await tryLinkIncidentToDisaster({
          disasterUuid: selectedDisasterPublicUuid,
          incidentUuid: linkDraft.incidentId,
          context: "linked",
        });
        if (!linkResult.ok) {
          toast.warning(linkResult.message);
        }
      }

      await completeRouteSuccess("success_existing_incident", {
        kind: "existing_incident",
        publicUuid: linkDraft.incidentId,
        incidentCode: selectedIncident?.incidentCode ?? "",
        incidentTitle: selectedIncident?.title ?? "Selected incident",
        linkType: linkDraft.linkType,
      });
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Intake link failed", err);
      }
      setRouteError(mapApiErrorToRouteMessage(err, "link"));
    } finally {
      setSubmittingRoute(null);
    }
  }, [
    activeIncidents,
    completeRouteSuccess,
    linkDraft,
    reportId,
    selectedDetail,
    selectedDisasterPublicUuid,
  ]);

  const handleSubmitDismiss = useCallback(async () => {
    if (!selectedDetail || !reportId) return;
    if (routeMode !== "duplicate" && routeMode !== "false_report") return;

    setSubmittingRoute(routeMode);
    setRouteError(null);

    try {
      const data = await dismissIntakeReport(reportId, {
        disposition: routeMode,
        note: dismissDraft.note.trim() || undefined,
      });

      const intakeReport = data.intake_report;
      const successMode =
        routeMode === "duplicate" ? "success_duplicate" : "success_false_report";

      await completeRouteSuccess(successMode, {
        kind: routeMode,
        reportCode:
          intakeReport?.report_code?.trim() || selectedDetail.reportCode,
        intakeStatus: intakeReport?.intake_status?.trim() || routeMode,
        note: dismissDraft.note.trim() || undefined,
      });
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Intake dismiss failed", err);
      }
      setRouteError(mapApiErrorToRouteMessage(err, routeMode));
    } finally {
      setSubmittingRoute(null);
    }
  }, [
    completeRouteSuccess,
    dismissDraft.note,
    reportId,
    routeMode,
    selectedDetail,
  ]);

  const clearSuccessAndResetOptions = useCallback(() => {
    clearRouteMutationState();
    setRouteMode("options");
  }, [clearRouteMutationState]);

  const handleOpenDetail = useCallback(() => {
    if (!routeResult) return;
    if (routeResult.kind === "service_case") {
      if (!routeResult.publicUuid) {
        toast.error("Service case link is unavailable. Refresh the queue.");
        return;
      }
      router.push(
        `/dashboard/dispatcher/service-cases/${encodeURIComponent(routeResult.publicUuid)}`,
      );
      return;
    }
    if (
      routeResult.kind === "emergency_incident" ||
      routeResult.kind === "existing_incident"
    ) {
      if (!routeResult.publicUuid) {
        toast.error("Incident link is unavailable. Refresh the queue.");
        return;
      }
      router.push(
        `/dashboard/dispatcher/incidents/${encodeURIComponent(routeResult.publicUuid)}`,
      );
    }
  }, [routeResult, router]);

  useEffect(() => {
    if (!enabled) {
      resetWorkflowState();
      return;
    }

    setRouteMode("options");
    clearRouteMutationState();
  }, [reportId, enabled, clearRouteMutationState, resetWorkflowState]);

  useEffect(() => {
    if (!enabled || !reportId) {
      return;
    }
    if (isSuccessRouteMode(routeMode)) return;
    void loadDetail(reportId);
  }, [enabled, reportId, loadDetail, routeMode]);

  useEffect(() => {
    if (!enabled || routeMode !== "existing_incident") return;
    void loadActiveIncidents();
  }, [enabled, routeMode, loadActiveIncidents]);

  const locationDialogItem = handoffItem ?? selectedDetail;
  const displayItem = handoffItem ?? selectedDetail;

  return {
    selectedDetail,
    handoffItem,
    displayItem,
    detailLoading,
    detailError,
    routeMode,
    serviceCaseDraft,
    emergencyDraft,
    linkDraft,
    routeResult,
    routeError,
    submittingRoute,
    dismissDraft,
    activeIncidents,
    incidentsLoading,
    incidentsError,
    locationDialogOpen,
    historyDialogOpen,
    locationDialogItem,
    selectedDisasterPublicUuid,
    isSuccessRouteMode: isSuccessRouteMode(routeMode),
    setServiceCaseDraft,
    setSelectedDisasterPublicUuid,
    setEmergencyDraft,
    setLinkDraft,
    setDismissDraft,
    setLocationDialogOpen,
    setHistoryDialogOpen,
    loadActiveIncidents,
    refreshAfterLocationUpdate,
    handleSelectRoute,
    handleBackToOptions,
    handleSubmitServiceCase,
    handleSubmitEmergency,
    handleSubmitLink,
    handleSubmitDismiss,
    clearSuccessAndResetOptions,
    handleOpenDetail,
    reporterRisk,
    reporterRiskLoading,
    verificationModalOpen,
    setVerificationModalOpen,
    setReporterRisk,
  };
}
