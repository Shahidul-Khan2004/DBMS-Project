"use client";

import { type FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { ChevronDown, ChevronUp } from "lucide-react";
import { useParams, useRouter } from "next/navigation";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { ConfirmModal } from "@/components/ui/ConfirmModal";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { EmptyState, PageLoading } from "@/components/ui/StatusState";
import { ApiError, apiGet, apiPatch, apiPost, ensureAuthSession } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import {
  formatBangladeshTime,
  getCurrentBangladeshDatetimeLocal,
  isValidBangladeshLocalDatetime,
  toBangladeshIsoDatetime,
} from "@/lib/datetime";
import {
  addIncidentAgency,
  createIncidentDispatch,
  getAvailableUnits,
  getIncidentResponseTiming,
  updateDispatchStatus,
} from "@/lib/dispatch-api";
import type {
  AgencyParticipation,
  AvailableUnit,
  Dispatch,
  DispatchPriorityLevel,
  ResponseTiming,
} from "@/types/dispatch";
import {
  type OperationsIntakeReport,
  type OperationsIntakeReportsResponse,
} from "@/types/operations-intake";

interface IncidentDetail {
  public_uuid: string;
  incident_code: string;
  title: string;
  description: string | null;
  origin_type: string;
  status_code: string;
  category_code: string;
  severity_code: string;
  outcome_code: string | null;
  reported_at: string | null;
  resolved_at: string | null;
  closed_at: string | null;
  created_at: string;
  updated_at: string;
}

interface LinkedIntakeReport {
  link_type: string;
  linked_at: string;
  intake_public_uuid: string;
  intake_report_code: string;
  intake_summary: string;
  intake_status: string;
  location?: {
    public_uuid: string;
    latitude: number;
    longitude: number;
    address_text: string | null;
    place_name: string | null;
    admin_area_id: number | null;
    source: string | null;
  } | null;
}

interface TimelineEvent {
  id: string;
  event_type: string;
  event_title: string;
  event_description: string | null;
  event_time: string;
  created_at: string;
}

interface IncidentResponse {
  incident: IncidentDetail;
  linked_intake_reports: LinkedIntakeReport[];
  timeline_preview: TimelineEvent[];
  dispatches?: Dispatch[];
}

interface StatusUpdateResponse {
  message?: string;
  incident: IncidentDetail;
}

interface NoteResponse {
  message?: string;
  note: {
    id: string;
    event_type: string;
    event_title: string;
    event_description: string | null;
  };
}

interface LinkIntakeResponse {
  message?: string;
}

type IntakeLinkType = "supporting_report" | "follow_up_report";

const DEFAULT_RECENT_INTAKE_LINK_TYPE: IntakeLinkType = "supporting_report";
const TERMINAL_STATUSES = ["resolved", "closed", "cancelled"];
const OUTCOME_OPTIONS = [
  "resolved",
  "false_alarm",
  "duplicate_incident",
  "cancelled",
  "transferred",
  "unresolved",
];
const DEMO_AGENCIES = [
  {
    publicUuid: "b2000001-0000-4000-8000-000000000001",
    name: "Dhaka Fire Service",
  },
  {
    publicUuid: "b2000001-0000-4000-8000-000000000002",
    name: "Dhaka Metropolitan Police",
  },
  {
    publicUuid: "b2000001-0000-4000-8000-000000000003",
    name: "Dhaka Emergency Medical Services",
  },
];
const DISPATCH_PRIORITY_OPTIONS: DispatchPriorityLevel[] = [
  "low",
  "medium",
  "high",
  "critical",
];
const DISPATCH_STATUS_TRANSITIONS: Record<string, string[]> = {
  assigned: ["dispatched", "cancelled"],
  dispatched: ["arrived", "cancelled"],
  arrived: ["completed", "cancelled"],
};

const ALLOWED_TRANSITIONS: Record<string, string[]> = {
  reported: ["classified", "cancelled"],
  classified: ["in_progress", "resolved", "closed", "cancelled"],
  in_progress: ["resolved", "closed", "cancelled"],
};

const labelClassName = "block text-sm font-medium text-gray-700";
const fieldClassName =
  "mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900 placeholder-gray-400 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35 disabled:cursor-not-allowed disabled:bg-gray-100 disabled:text-gray-500";
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function getAllowedTransitions(statusCode: string) {
  return ALLOWED_TRANSITIONS[statusCode] ?? [];
}

function isTerminalStatus(statusCode: string) {
  return TERMINAL_STATUSES.includes(statusCode);
}

function getDefaultOutcome(statusCode: string) {
  return statusCode === "cancelled" ? "cancelled" : "resolved";
}

function formatApiError(error: unknown, fallback: string) {
  if (error instanceof ApiError) {
    const hints: Record<string, string> = {
      AGENCY_ALREADY_PARTICIPATING:
        "This agency is already participating in the incident.",
      AGENCY_NOT_FOUND: "The selected agency could not be found.",
      AGENCY_NOT_PARTICIPATING:
        "Add the unit's agency to this incident before dispatching the unit.",
      DISPATCH_ALREADY_EXISTS:
        "This unit already has a dispatch for the incident.",
      EMERGENCY_INCIDENT_REQUIRES_LOCATION:
        "Add a reported location to the intake report before linking it.",
      INCIDENT_NOT_FOUND: "The incident could not be found.",
      INTAKE_ALREADY_LINKED:
        "This intake report is already linked to an emergency incident.",
      INTAKE_NOT_PROMOTABLE:
        "This intake report cannot be linked in its current status.",
      INCIDENT_NOT_LINKABLE:
        "This incident cannot accept new intake links.",
      INVALID_STATUS_CODE: "Choose a valid dispatch status.",
      INVALID_STATUS_TRANSITION:
        "That dispatch status transition is not allowed.",
      UNIT_NOT_AVAILABLE:
        "The selected unit is no longer available. Refresh units and try again.",
      UNIT_NOT_FOUND: "The selected unit could not be found.",
    };
    const hint = error.code ? hints[error.code] : undefined;
    const codePrefix = error.code ? `${error.code}: ` : "";
    return `${codePrefix}${error.message}${hint ? ` ${hint}` : ""}`;
  }

  return error instanceof Error ? error.message : fallback;
}

function DetailItem({
  label,
  value,
}: {
  label: string;
  value: string | null | undefined;
}) {
  return (
    <div>
      <dt className="text-sm font-medium text-gray-600">{label}</dt>
      <dd className="mt-1 break-words text-sm text-gray-900">
        {value?.toString().trim() || "-"}
      </dd>
    </div>
  );
}

function formatLocation(report: LinkedIntakeReport) {
  const location = report.location;
  if (!location) return "-";
  return (
    location.address_text ||
    location.place_name ||
    "Map location selected"
  );
}

function formatRecentReportLocation(report: OperationsIntakeReport) {
  return (
    report.location_text ||
    report.location?.address_text ||
    report.location?.place_name ||
    "Location unavailable"
  );
}

function formatMinuteValue(value: number | null | undefined) {
  if (value === null || value === undefined) return "N/A";
  return `${value} min`;
}

function formatMilestoneValue(value: string | null | undefined) {
  return value ? formatBangladeshTime(value) : "Not yet reached";
}

function getDispatchTransitions(statusCode: string) {
  return DISPATCH_STATUS_TRANSITIONS[statusCode] ?? [];
}

function mergeDispatches(current: Dispatch[], nextDispatch: Dispatch) {
  const existingIndex = current.findIndex(
    (dispatch) => dispatch.public_uuid === nextDispatch.public_uuid,
  );

  if (existingIndex === -1) return [nextDispatch, ...current];

  return current.map((dispatch, index) =>
    index === existingIndex ? nextDispatch : dispatch,
  );
}

export default function IncidentDetailPage() {
  const params = useParams();
  const router = useRouter();
  const incidentPublicUuid = params.incidentPublicUuid as string;

  const [isLoadingSession, setIsLoadingSession] = useState(true);
  const [incident, setIncident] = useState<IncidentDetail | null>(null);
  const [linkedReports, setLinkedReports] = useState<LinkedIntakeReport[]>([]);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [statusCode, setStatusCode] = useState("");
  const [statusNote, setStatusNote] = useState("");
  const [outcomeCode, setOutcomeCode] = useState("resolved");
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);
  const [confirmStatusOpen, setConfirmStatusOpen] = useState(false);
  const [statusUpdateError, setStatusUpdateError] = useState<string | null>(null);
  const [statusUpdateSuccess, setStatusUpdateSuccess] = useState<string | null>(
    null,
  );
  const [noteTitle, setNoteTitle] = useState("");
  const [noteDescription, setNoteDescription] = useState("");
  const [noteEventTime, setNoteEventTime] = useState(
    getCurrentBangladeshDatetimeLocal(),
  );
  const [isAddingNote, setIsAddingNote] = useState(false);
  const [noteError, setNoteError] = useState<string | null>(null);
  const [noteSuccess, setNoteSuccess] = useState<string | null>(null);
  const [linkModalOpen, setLinkModalOpen] = useState(false);
  const [linkIntakeUuid, setLinkIntakeUuid] = useState("");
  const [linkType, setLinkType] =
    useState<IntakeLinkType>(DEFAULT_RECENT_INTAKE_LINK_TYPE);
  const [linkNote, setLinkNote] = useState("");
  const [recentReportsExpanded, setRecentReportsExpanded] = useState(false);
  const [isLinkingIntake, setIsLinkingIntake] = useState(false);
  const [linkError, setLinkError] = useState<string | null>(null);
  const [linkSuccess, setLinkSuccess] = useState<string | null>(null);
  const [recentIntakeReports, setRecentIntakeReports] = useState<OperationsIntakeReport[]>([]);
  const [loadingRecentReports, setLoadingRecentReports] = useState(false);
  const [agencyPublicUuid, setAgencyPublicUuid] = useState(
    DEMO_AGENCIES[0]?.publicUuid ?? "",
  );
  const [isLeadAgency, setIsLeadAgency] = useState(false);
  const [agencyParticipations, setAgencyParticipations] = useState<AgencyParticipation[]>([]);
  const [agencyLoading, setAgencyLoading] = useState(false);
  const [dispatchMessage, setDispatchMessage] = useState<string | null>(null);
  const [dispatchError, setDispatchError] = useState<string | null>(null);
  const [availableUnits, setAvailableUnits] = useState<AvailableUnit[]>([]);
  const [unitsLoading, setUnitsLoading] = useState(false);
  const [unitsError, setUnitsError] = useState<string | null>(null);
  const [selectedUnitUuid, setSelectedUnitUuid] = useState("");
  const [priorityLevel, setPriorityLevel] =
    useState<DispatchPriorityLevel>("medium");
  const [dispatchNote, setDispatchNote] = useState("");
  const [dispatches, setDispatches] = useState<Dispatch[]>([]);
  const [isCreatingDispatch, setIsCreatingDispatch] = useState(false);
  const [dispatchStatusSelections, setDispatchStatusSelections] = useState<
    Record<string, string>
  >({});
  const [dispatchStatusNotes, setDispatchStatusNotes] = useState<
    Record<string, string>
  >({});
  const [updatingDispatchUuid, setUpdatingDispatchUuid] = useState<string | null>(
    null,
  );
  const [responseTiming, setResponseTiming] = useState<ResponseTiming | null>(null);
  const [responseTimingLoading, setResponseTimingLoading] = useState(false);
  const [responseTimingError, setResponseTimingError] = useState<string | null>(null);

  const redirectToLogin = useCallback(() => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/auth/login");
  }, [router]);

  const loadIncident = useCallback(async () => {
    const accessToken = await ensureAuthSession();
    if (!accessToken) {
      redirectToLogin();
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const data = await apiGet<IncidentResponse>(
        `/operations/incidents/${incidentPublicUuid}`,
      );
      setIncident(data.incident);
      setLinkedReports(data.linked_intake_reports ?? []);
      setTimeline(data.timeline_preview ?? []);
      if (Array.isArray(data.dispatches)) {
        setDispatches(data.dispatches);
      }
    } catch (err) {
      setError(formatApiError(err, "Unexpected error while loading incident."));
      setIncident(null);
      setLinkedReports([]);
      setTimeline([]);
    } finally {
      setLoading(false);
    }
  }, [incidentPublicUuid, redirectToLogin]);

  const loadRecentIntakeReports = useCallback(async () => {
    setLoadingRecentReports(true);
    try {
      const data = await apiGet<OperationsIntakeReportsResponse>(
        `/operations/intake-reports?limit=10&sort=reported_at_desc`,
      );
      setRecentIntakeReports(data.intake_reports ?? []);
    } catch (err) {
      console.error("Failed to load recent intake reports:", err);
      setRecentIntakeReports([]);
    } finally {
      setLoadingRecentReports(false);
    }
  }, []);

  const loadAvailableUnits = useCallback(async () => {
    setUnitsLoading(true);
    setUnitsError(null);

    try {
      const data = await getAvailableUnits(incidentPublicUuid);
      setAvailableUnits(data.units ?? []);
      setSelectedUnitUuid((current) => {
        if (current && data.units?.some((unit) => unit.public_uuid === current)) {
          return current;
        }
        return data.units?.[0]?.public_uuid ?? "";
      });
    } catch (err) {
      setUnitsError(formatApiError(err, "Could not load available units."));
      setAvailableUnits([]);
      setSelectedUnitUuid("");
    } finally {
      setUnitsLoading(false);
    }
  }, [incidentPublicUuid]);

  const loadResponseTiming = useCallback(async () => {
    setResponseTimingLoading(true);
    setResponseTimingError(null);

    try {
      const data = await getIncidentResponseTiming(incidentPublicUuid);
      setResponseTiming(data.timing ?? null);
    } catch (err) {
      setResponseTimingError(
        formatApiError(err, "Could not load response timing."),
      );
      setResponseTiming(null);
    } finally {
      setResponseTimingLoading(false);
    }
  }, [incidentPublicUuid]);

  const refreshIncidentPage = useCallback(async () => {
    await Promise.all([
      loadIncident(),
      loadRecentIntakeReports(),
      loadAvailableUnits(),
      loadResponseTiming(),
    ]);
  }, [
    loadAvailableUnits,
    loadIncident,
    loadRecentIntakeReports,
    loadResponseTiming,
  ]);

  useEffect(() => {
    let cancelled = false;

    async function checkSession() {
      const accessToken = await ensureAuthSession();
      const sessionUser = sessionStorage.getItem("loggedInUser");

      if (cancelled) return;

      if (!sessionUser || !accessToken) {
        redirectToLogin();
        return;
      }

      setIsLoadingSession(false);
    }

    void checkSession();

    return () => {
      cancelled = true;
    };
  }, [redirectToLogin]);

  useEffect(() => {
    if (isLoadingSession || !incidentPublicUuid) return;
    void loadIncident();
  }, [isLoadingSession, incidentPublicUuid, loadIncident]);

  useEffect(() => {
    if (isLoadingSession) return;
    void loadRecentIntakeReports();
  }, [isLoadingSession, loadRecentIntakeReports]);

  useEffect(() => {
    if (isLoadingSession || !incidentPublicUuid) return;
    void loadAvailableUnits();
    void loadResponseTiming();
  }, [
    incidentPublicUuid,
    isLoadingSession,
    loadAvailableUnits,
    loadResponseTiming,
  ]);

  useEffect(() => {
    if (!incident) return;

    const allowed = getAllowedTransitions(incident.status_code);
    setStatusCode(allowed[0] ?? "");
    setOutcomeCode(incident.outcome_code ?? "resolved");
  }, [incident]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  const allowedTransitions = useMemo(
    () => (incident ? getAllowedTransitions(incident.status_code) : []),
    [incident],
  );
  const currentStatusIsTerminal = incident
    ? isTerminalStatus(incident.status_code)
    : false;
  const canManageDispatchActions = Boolean(incident) && !currentStatusIsTerminal;
  const canUpdateStatus =
    Boolean(incident) && !currentStatusIsTerminal && allowedTransitions.length > 0;
  const shouldSendOutcome = isTerminalStatus(statusCode);

  const handleStatusChange = (nextStatusCode: string) => {
    setStatusCode(nextStatusCode);
    setStatusUpdateError(null);
    setStatusUpdateSuccess(null);

    setOutcomeCode(
      isTerminalStatus(nextStatusCode) ? getDefaultOutcome(nextStatusCode) : "resolved",
    );
  };

  const updateIncidentStatus = async () => {
    if (!incident || !statusCode) return;

    setIsUpdatingStatus(true);
    setStatusUpdateError(null);
    setStatusUpdateSuccess(null);

    try {
      const responseData = await apiPatch<StatusUpdateResponse>(
        `/operations/incidents/${incidentPublicUuid}/status`,
        {
          statusCode,
          note: statusNote.trim() || undefined,
          ...(shouldSendOutcome ? { outcomeCode } : {}),
        },
      );
      setIncident(responseData.incident);
      setStatusNote("");
      setStatusUpdateSuccess(responseData.message ?? "Incident status updated.");
      await loadIncident();
    } catch (err) {
      setStatusUpdateError(
        formatApiError(err, "Unexpected error while updating incident status."),
      );
    } finally {
      setIsUpdatingStatus(false);
      setConfirmStatusOpen(false);
    }
  };

  const handleNoteSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!incident || !noteTitle.trim()) return;

    setIsAddingNote(true);
    setNoteError(null);
    setNoteSuccess(null);

    if (noteEventTime && !isValidBangladeshLocalDatetime(noteEventTime)) {
      setNoteError("Event time must be a valid Bangladesh date and time.");
      setIsAddingNote(false);
      return;
    }

    try {
      const responseData = await apiPost<NoteResponse>(
        `/operations/incidents/${incidentPublicUuid}/notes`,
        {
          title: noteTitle.trim(),
          description: noteDescription.trim() || undefined,
          eventTime: toBangladeshIsoDatetime(noteEventTime),
        },
      );

      setNoteTitle("");
      setNoteDescription("");
      setNoteEventTime(getCurrentBangladeshDatetimeLocal());
      setNoteSuccess(responseData.message ?? "Operator note added.");
      await loadIncident();
    } catch (err) {
      setNoteError(formatApiError(err, "Unexpected error while adding note."));
    } finally {
      setIsAddingNote(false);
    }
  };

  const linkedReportUuidSet = useMemo(
    () => new Set(linkedReports.map((report) => report.intake_public_uuid)),
    [linkedReports],
  );
  const visibleRecentIntakeReports = useMemo(
    () => {
      return [...recentIntakeReports]
        .filter(
          (report) =>
            !report.has_incident && !linkedReportUuidSet.has(report.public_uuid),
        )
        .sort((leftReport, rightReport) => {
          const leftTime = Date.parse(
            leftReport.reported_at ??
              leftReport.created_at ??
              leftReport.updated_at,
          );
          const rightTime = Date.parse(
            rightReport.reported_at ??
              rightReport.created_at ??
              rightReport.updated_at,
          );

          return (Number.isNaN(rightTime) ? 0 : rightTime) -
            (Number.isNaN(leftTime) ? 0 : leftTime);
        });
    },
    [linkedReportUuidSet, recentIntakeReports],
  );
  const openLinkModal = () => {
    setLinkError(null);
    setLinkSuccess(null);
    setLinkModalOpen(true);
  };

  const handleAgencySubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!agencyPublicUuid) return;
    if (currentStatusIsTerminal) {
      setDispatchError(
        "This incident is final. Agency and dispatch actions are disabled.",
      );
      return;
    }

    setAgencyLoading(true);
    setDispatchError(null);
    setDispatchMessage(null);

    try {
      const data = await addIncidentAgency(incidentPublicUuid, {
        agencyPublicUuid,
        isLeadAgency,
      });
      setAgencyParticipations((current) => [
        data.participation,
        ...current.filter(
          (item) => item.agency_public_uuid !== data.participation.agency_public_uuid,
        ),
      ]);
      setDispatchMessage(data.message ?? "Agency added to incident.");
      setIsLeadAgency(false);
      await Promise.all([loadIncident(), loadAvailableUnits(), loadResponseTiming()]);
    } catch (err) {
      setDispatchError(formatApiError(err, "Could not add agency to incident."));
    } finally {
      setAgencyLoading(false);
    }
  };

  const handleCreateDispatch = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (currentStatusIsTerminal) {
      setDispatchError(
        "This incident is final. Agency and dispatch actions are disabled.",
      );
      return;
    }
    if (!selectedUnitUuid) {
      setDispatchError("Select an available unit to create a dispatch.");
      return;
    }

    setIsCreatingDispatch(true);
    setDispatchError(null);
    setDispatchMessage(null);

    try {
      const data = await createIncidentDispatch(incidentPublicUuid, {
        unitPublicUuid: selectedUnitUuid,
        priorityLevel,
        note: dispatchNote.trim() || undefined,
      });
      setDispatches((current) => mergeDispatches(current, data.dispatch));
      setDispatchStatusSelections((current) => ({
        ...current,
        [data.dispatch.public_uuid]:
          getDispatchTransitions(data.dispatch.status_code)[0] ?? "",
      }));
      setDispatchNote("");
      setDispatchMessage(data.message ?? "Dispatch created.");
      await Promise.all([loadIncident(), loadAvailableUnits(), loadResponseTiming()]);
    } catch (err) {
      setDispatchError(formatApiError(err, "Could not create dispatch."));
    } finally {
      setIsCreatingDispatch(false);
    }
  };

  const handleDispatchStatusUpdate = async (dispatch: Dispatch) => {
    if (currentStatusIsTerminal) {
      setDispatchError(
        "This incident is final. Agency and dispatch actions are disabled.",
      );
      return;
    }
    const nextStatus =
      dispatchStatusSelections[dispatch.public_uuid] ??
      getDispatchTransitions(dispatch.status_code)[0] ??
      "";

    if (!nextStatus) return;

    setUpdatingDispatchUuid(dispatch.public_uuid);
    setDispatchError(null);
    setDispatchMessage(null);

    try {
      const data = await updateDispatchStatus(dispatch.public_uuid, {
        statusCode: nextStatus,
        note: dispatchStatusNotes[dispatch.public_uuid]?.trim() || undefined,
      });
      setDispatches((current) => mergeDispatches(current, data.dispatch));
      setDispatchStatusNotes((current) => ({
        ...current,
        [dispatch.public_uuid]: "",
      }));
      setDispatchStatusSelections((current) => ({
        ...current,
        [dispatch.public_uuid]:
          getDispatchTransitions(data.dispatch.status_code)[0] ?? "",
      }));
      setDispatchMessage(data.message ?? "Dispatch status updated.");
      await Promise.all([loadIncident(), loadAvailableUnits(), loadResponseTiming()]);
    } catch (err) {
      setDispatchError(formatApiError(err, "Could not update dispatch status."));
    } finally {
      setUpdatingDispatchUuid(null);
    }
  };

  const closeLinkModal = () => {
    if (isLinkingIntake) return;
    setLinkModalOpen(false);
    setLinkError(null);
  };

  const handleLinkIntakeSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!incident) return;

    const trimmedIntakeUuid = linkIntakeUuid.trim();

    if (!UUID_PATTERN.test(trimmedIntakeUuid)) {
      setLinkError("Enter a valid intake report public UUID.");
      return;
    }

    if (linkNote.trim().length > 500) {
      setLinkError("Link note must be 500 characters or fewer.");
      return;
    }

    setIsLinkingIntake(true);
    setLinkError(null);
    setLinkSuccess(null);

    try {
      const data = await apiPost<LinkIntakeResponse>(
        `/operations/incidents/${incidentPublicUuid}/intake-reports`,
        {
          intakeReportPublicUuid: trimmedIntakeUuid,
          linkType,
          note: linkNote.trim() || undefined,
        },
      );

      setLinkIntakeUuid("");
      setLinkType(DEFAULT_RECENT_INTAKE_LINK_TYPE);
      setLinkNote("");
      setLinkModalOpen(false);
      setLinkSuccess(data.message ?? "Intake report linked to incident.");
      await loadIncident();
      await loadRecentIntakeReports();
    } catch (err) {
      setLinkError(formatApiError(err, "Could not link intake report."));
    } finally {
      setIsLinkingIntake(false);
    }
  };

  if (isLoadingSession) {
    return <PageLoading label="Loading incident details" />;
  }

  return (
    <DashboardLayout
      title="Incident Details"
      subtitle={`Incident ${incident?.incident_code || incidentPublicUuid}`}
      onLogout={handleLogout}
    >
      <div className="space-y-6">
        <ConfirmModal
          open={confirmStatusOpen}
          title="Update incident status?"
          message={`This will change the incident from ${
            incident?.status_code ?? "current status"
          } to ${statusCode}.`}
          confirmLabel="Update Status"
          isLoading={isUpdatingStatus}
          onConfirm={() => void updateIncidentStatus()}
          onCancel={() => setConfirmStatusOpen(false)}
        />

        {linkModalOpen ? (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4">
            <div className="w-full max-w-lg rounded-3xl bg-white p-6 shadow-xl">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <h2 className="text-lg font-semibold text-[#002D62]">
                    Link Intake Report
                  </h2>
                  <p className="mt-1 text-sm leading-6 text-gray-600">
                    Add an existing intake report to this incident as a
                    supporting or follow-up report.
                  </p>
                </div>
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  onClick={closeLinkModal}
                  disabled={isLinkingIntake}
                >
                  Close
                </Button>
              </div>

              {linkError ? (
                <div className="mt-4 rounded-2xl bg-red-50 p-3 text-sm text-red-700">
                  {linkError}
                </div>
              ) : null}

              <form onSubmit={handleLinkIntakeSubmit} className="mt-5 space-y-4">
                <div>
                  <label className={labelClassName}>
                    Intake Report Public UUID
                  </label>
                  <input
                    value={linkIntakeUuid}
                    onChange={(event) => {
                      setLinkIntakeUuid(event.target.value);
                      setLinkError(null);
                    }}
                    className={fieldClassName}
                    placeholder="0d5fd834-a3fc-4180-b8ec-a6e664d130d0"
                    disabled={isLinkingIntake}
                    required
                  />
                </div>

                <div>
                  <label className={labelClassName}>Link Type</label>
                  <select
                    value={linkType}
                    onChange={(event) =>
                      setLinkType(event.target.value as IntakeLinkType)
                    }
                    className={fieldClassName}
                    disabled={isLinkingIntake}
                  >
                    <option value="supporting_report">Supporting Report</option>
                    <option value="follow_up_report">Follow-up Report</option>
                  </select>
                </div>

                <div>
                  <label className={labelClassName}>Note</label>
                  <textarea
                    value={linkNote}
                    onChange={(event) => setLinkNote(event.target.value)}
                    className={fieldClassName}
                    rows={3}
                    maxLength={500}
                    placeholder="Optional note"
                    disabled={isLinkingIntake}
                  />
                </div>

                <div className="flex justify-end gap-3">
                  <Button
                    type="button"
                    variant="secondary"
                    onClick={closeLinkModal}
                    disabled={isLinkingIntake}
                  >
                    Cancel
                  </Button>
                  <Button
                    type="submit"
                    isLoading={isLinkingIntake}
                    disabled={isLinkingIntake || !linkIntakeUuid.trim()}
                  >
                    Link Intake Report
                  </Button>
                </div>
              </form>
            </div>
          </div>
        ) : null}

        <div className="flex flex-wrap items-center gap-3">
          <Button
            type="button"
            variant="secondary"
            onClick={() => router.push("/dashboard/dispatcher/incidents")}
          >
            Back to Incidents
          </Button>
          <Button
            type="button"
            variant="secondary"
            onClick={() => void refreshIncidentPage()}
            disabled={loading || loadingRecentReports}
          >
            {loading || loadingRecentReports ? "Loading..." : "Refresh"}
          </Button>
        </div>

        {error && <ErrorAlert message={error} />}
        {loading && !incident ? <LoadingSkeleton lines={8} /> : null}

        {!loading && !incident && !error ? (
          <EmptyState
            title="Incident not found"
            description="The backend did not return an incident for this identifier. Return to the incident list and try again."
          />
        ) : null}

        {incident ? (
          <div className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_480px]">
            <div className="space-y-6">
              <div className="max-w-4xl">
              <Card className="shadow-md">
                <CardHeader>
                  <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
                    <div>
                      <p className="text-sm font-bold uppercase tracking-wide text-gray-600">
                        {incident.incident_code}
                      </p>
                      <h1 className="mt-1 text-2xl font-bold text-[#002D62]">
                        {incident.title}
                      </h1>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <Badge tone={incident.status_code}>
                        {formatBadgeLabel(incident.status_code)}
                      </Badge>
                      <Badge tone={incident.severity_code}>
                        {formatBadgeLabel(incident.severity_code)}
                      </Badge>
                      <Badge tone={incident.category_code}>
                        {formatBadgeLabel(incident.category_code)}
                      </Badge>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-5">
                  <div>
                    <h2 className="text-sm font-semibold text-gray-900">
                      Description
                    </h2>
                    <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-gray-700">
                      {incident.description?.trim() ||
                        "No description provided."}
                    </p>
                  </div>

                  <dl className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                    <DetailItem
                      label="Origin"
                      value={formatBadgeLabel(incident.origin_type)}
                    />
                    <DetailItem
                      label="Outcome"
                      value={
                        incident.outcome_code
                          ? formatBadgeLabel(incident.outcome_code)
                          : null
                      }
                    />
                    <DetailItem
                      label="Reported At"
                      value={formatBangladeshTime(incident.reported_at)}
                    />
                    <DetailItem
                      label="Public UUID"
                      value={incident.public_uuid}
                    />
                  </dl>
                </CardContent>
              </Card>
              </div>

                <Card className="shadow-md">
                  <CardHeader>
                    <h2 className="text-lg font-semibold text-[#002D62]">
                      Full Incident Detail
                    </h2>
                  </CardHeader>
                  <CardContent>
                    <dl className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
                      <DetailItem label="Incident Code" value={incident.incident_code} />
                      <DetailItem label="Status" value={incident.status_code} />
                      <DetailItem label="Severity" value={incident.severity_code} />
                      <DetailItem label="Category" value={incident.category_code} />
                      <DetailItem label="Origin Type" value={incident.origin_type} />
                      <DetailItem label="Outcome Code" value={incident.outcome_code} />
                      <DetailItem
                        label="Reported At"
                        value={formatBangladeshTime(incident.reported_at)}
                      />
                      <DetailItem
                        label="Resolved At"
                        value={formatBangladeshTime(incident.resolved_at)}
                      />
                      <DetailItem
                        label="Closed At"
                        value={formatBangladeshTime(incident.closed_at)}
                      />
                      <DetailItem
                        label="Created At"
                        value={formatBangladeshTime(incident.created_at)}
                      />
                      <DetailItem
                        label="Updated At"
                        value={formatBangladeshTime(incident.updated_at)}
                      />
                    </dl>
                  </CardContent>
                </Card>

                <Card className="shadow-md">
                  <CardHeader>
                    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                      <div>
                        <h2 className="text-lg font-semibold text-[#002D62]">
                          Dispatch & Response
                        </h2>
                        <p className="mt-1 text-sm text-gray-600">
                          Assign agencies, dispatch available units, and monitor response timing.
                        </p>
                      </div>
                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        onClick={() =>
                          void Promise.all([
                            loadAvailableUnits(),
                            loadResponseTiming(),
                            loadIncident(),
                          ])
                        }
                        disabled={unitsLoading || responseTimingLoading || loading}
                      >
                        Refresh
                      </Button>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-8">
                    {dispatchError ? (
                      <div className="rounded-2xl bg-red-50 p-3 text-sm text-red-700">
                        {dispatchError}
                      </div>
                    ) : null}
                    {dispatchMessage ? (
                      <div className="rounded-2xl bg-green-50 p-3 text-sm text-green-700">
                        {dispatchMessage}
                      </div>
                    ) : null}
                    {currentStatusIsTerminal ? (
                      <div className="rounded-2xl bg-slate-50 p-3 text-sm text-slate-700">
                        This incident is final. Agency assignment and dispatch actions are disabled.
                      </div>
                    ) : null}

                    <section>
                      <h3 className="text-sm font-semibold text-gray-900">
                        Agency Assignment
                      </h3>
                      <form
                        onSubmit={handleAgencySubmit}
                        className="mt-4 grid gap-4 md:grid-cols-[minmax(0,1fr)_auto]"
                      >
                        <div>
                          <label className={labelClassName}>Participating Agency</label>
                          <select
                            value={agencyPublicUuid}
                            onChange={(event) => setAgencyPublicUuid(event.target.value)}
                            className={fieldClassName}
                            disabled={agencyLoading || currentStatusIsTerminal}
                          >
                            {DEMO_AGENCIES.map((agency) => (
                              <option key={agency.publicUuid} value={agency.publicUuid}>
                                {agency.name}
                              </option>
                            ))}
                          </select>
                        </div>
                        <div className="flex items-end">
                          <label className="flex min-h-[42px] items-center gap-2 rounded-2xl border border-[#002D62]/20 px-3 py-2 text-sm font-medium text-gray-700">
                            <input
                              type="checkbox"
                              checked={isLeadAgency}
                              onChange={(event) => setIsLeadAgency(event.target.checked)}
                              disabled={agencyLoading || currentStatusIsTerminal}
                              className="h-4 w-4 rounded border-gray-300 text-[#006747] focus:ring-[#006747]"
                            />
                            Lead agency
                          </label>
                        </div>
                        <div className="md:col-span-2">
                          <Button
                            type="submit"
                            isLoading={agencyLoading}
                            disabled={
                              agencyLoading || !agencyPublicUuid || currentStatusIsTerminal
                            }
                          >
                            Add Agency
                          </Button>
                        </div>
                      </form>

                      {agencyParticipations.length > 0 ? (
                        <ul className="mt-4 space-y-2">
                          {agencyParticipations.map((participation) => (
                            <li
                              key={participation.agency_public_uuid}
                              className="rounded-lg border border-[#002D62]/10 p-3 text-sm text-gray-700"
                            >
                              <span className="font-semibold text-gray-900">
                                {participation.agency_name}
                              </span>{" "}
                              joined {formatBangladeshTime(participation.joined_at)}
                              {participation.is_lead_agency ? " as lead agency" : ""}
                            </li>
                          ))}
                        </ul>
                      ) : null}
                    </section>

                    <section className="border-t border-[#002D62]/10 pt-6">
                      <h3 className="text-sm font-semibold text-gray-900">
                        Available Units
                      </h3>
                      {unitsLoading ? (
                        <div className="mt-4">
                          <LoadingSkeleton lines={3} />
                        </div>
                      ) : unitsError ? (
                        <div className="mt-4 rounded-2xl bg-red-50 p-3 text-sm text-red-700">
                          {unitsError}
                        </div>
                      ) : availableUnits.length === 0 ? (
                        <p className="mt-4 text-sm text-gray-600">
                          No available units. Add an agency first or wait for units to become available.
                        </p>
                      ) : (
                        <div className="mt-4 overflow-x-auto">
                          <table className="min-w-full divide-y divide-gray-100 text-sm">
                            <thead>
                              <tr className="text-left text-xs font-semibold uppercase tracking-wide text-gray-500">
                                <th className="py-2 pr-4">Unit</th>
                                <th className="py-2 pr-4">Type</th>
                                <th className="py-2 pr-4">Agency</th>
                                <th className="py-2 pr-4">Status</th>
                              </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-100">
                              {availableUnits.map((unit) => (
                                <tr key={unit.public_uuid}>
                                  <td className="py-3 pr-4">
                                    <p className="font-medium text-gray-900">
                                      {unit.unit_name}
                                    </p>
                                    <p className="text-xs text-gray-500">
                                      {unit.unit_code}
                                    </p>
                                  </td>
                                  <td className="py-3 pr-4 text-gray-700">
                                    {formatBadgeLabel(unit.unit_type_code)}
                                  </td>
                                  <td className="py-3 pr-4 text-gray-700">
                                    {unit.agency_name}
                                  </td>
                                  <td className="py-3 pr-4">
                                    <Badge tone={unit.status_code}>
                                      {formatBadgeLabel(unit.status_code)}
                                    </Badge>
                                  </td>
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </section>

                    <section className="border-t border-[#002D62]/10 pt-6">
                      <h3 className="text-sm font-semibold text-gray-900">
                        Create Dispatch
                      </h3>
                      <form onSubmit={handleCreateDispatch} className="mt-4 space-y-4">
                        <div className="grid gap-4 md:grid-cols-2">
                          <div>
                            <label className={labelClassName}>Unit</label>
                            <select
                              value={selectedUnitUuid}
                              onChange={(event) => setSelectedUnitUuid(event.target.value)}
                              className={fieldClassName}
                              disabled={
                                isCreatingDispatch ||
                                availableUnits.length === 0 ||
                                currentStatusIsTerminal
                              }
                              required
                            >
                              {availableUnits.length === 0 ? (
                                <option value="">No available units</option>
                              ) : (
                                availableUnits.map((unit) => (
                                  <option key={unit.public_uuid} value={unit.public_uuid}>
                                    {unit.unit_name} ({unit.unit_code})
                                  </option>
                                ))
                              )}
                            </select>
                          </div>
                          <div>
                            <label className={labelClassName}>Priority</label>
                            <select
                              value={priorityLevel}
                              onChange={(event) =>
                                setPriorityLevel(event.target.value as DispatchPriorityLevel)
                              }
                              className={fieldClassName}
                              disabled={isCreatingDispatch || currentStatusIsTerminal}
                            >
                              {DISPATCH_PRIORITY_OPTIONS.map((priority) => (
                                <option key={priority} value={priority}>
                                  {formatBadgeLabel(priority)}
                                </option>
                              ))}
                            </select>
                          </div>
                        </div>
                        <div>
                          <label className={labelClassName}>Note</label>
                          <textarea
                            value={dispatchNote}
                            onChange={(event) => setDispatchNote(event.target.value)}
                            className={fieldClassName}
                            rows={3}
                            placeholder="Optional dispatch note"
                            disabled={
                              isCreatingDispatch || currentStatusIsTerminal
                            }
                          />
                        </div>
                        <Button
                          type="submit"
                          isLoading={isCreatingDispatch}
                          disabled={
                            isCreatingDispatch ||
                            availableUnits.length === 0 ||
                            !selectedUnitUuid ||
                            currentStatusIsTerminal
                          }
                        >
                          Create Dispatch
                        </Button>
                      </form>
                    </section>

                    <section className="border-t border-[#002D62]/10 pt-6">
                      <h3 className="text-sm font-semibold text-gray-900">
                        Dispatch Status Controls
                      </h3>
                      {dispatches.length === 0 ? (
                        <p className="mt-4 text-sm text-gray-600">
                          No dispatches are available from this page session. Existing dispatches can only be listed after refresh if the incident detail endpoint returns them.
                        </p>
                      ) : (
                        <ul className="mt-4 space-y-4">
                          {dispatches.map((dispatch) => {
                            const transitions = getDispatchTransitions(dispatch.status_code);
                            const selectedStatus =
                              dispatchStatusSelections[dispatch.public_uuid] ??
                              transitions[0] ??
                              "";

                            return (
                              <li
                                key={dispatch.public_uuid}
                                className="rounded-lg border border-[#002D62]/10 p-4"
                              >
                                <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                                  <div>
                                    <div className="flex flex-wrap items-center gap-2">
                                      <Badge tone={dispatch.status_code}>
                                        {formatBadgeLabel(dispatch.status_code)}
                                      </Badge>
                                      <Badge tone={dispatch.priority_level}>
                                        {formatBadgeLabel(dispatch.priority_level)}
                                      </Badge>
                                    </div>
                                    <p className="mt-2 break-all text-sm font-medium text-gray-900">
                                      Dispatch {dispatch.public_uuid}
                                    </p>
                                    <p className="mt-1 break-all text-xs text-gray-500">
                                      Unit {dispatch.unit_public_uuid}
                                    </p>
                                  </div>
                                  <div className="text-xs text-gray-500 md:text-right">
                                    <p>Assigned {formatMilestoneValue(dispatch.assigned_at)}</p>
                                    <p>Dispatched {formatMilestoneValue(dispatch.dispatched_at)}</p>
                                    <p>Arrived {formatMilestoneValue(dispatch.arrived_at)}</p>
                                  </div>
                                </div>

                                {transitions.length === 0 ? (
                                  <p className="mt-4 text-sm text-gray-600">
                                    This dispatch is terminal.
                                  </p>
                                ) : (
                                  <div className="mt-4 grid gap-3 md:grid-cols-[minmax(0,180px)_minmax(0,1fr)_auto]">
                                    <select
                                      value={selectedStatus}
                                      onChange={(event) =>
                                        setDispatchStatusSelections((current) => ({
                                          ...current,
                                          [dispatch.public_uuid]: event.target.value,
                                        }))
                                      }
                                      className={fieldClassName}
                                      disabled={
                                        updatingDispatchUuid === dispatch.public_uuid ||
                                        currentStatusIsTerminal
                                      }
                                    >
                                      {transitions.map((status) => (
                                        <option key={status} value={status}>
                                          {formatBadgeLabel(status)}
                                        </option>
                                      ))}
                                    </select>
                                    <input
                                      value={dispatchStatusNotes[dispatch.public_uuid] ?? ""}
                                      onChange={(event) =>
                                        setDispatchStatusNotes((current) => ({
                                          ...current,
                                          [dispatch.public_uuid]: event.target.value,
                                        }))
                                      }
                                      className={fieldClassName}
                                      placeholder="Optional status note"
                                      disabled={
                                        updatingDispatchUuid === dispatch.public_uuid ||
                                        currentStatusIsTerminal
                                      }
                                    />
                                    <Button
                                      type="button"
                                      isLoading={updatingDispatchUuid === dispatch.public_uuid}
                                      disabled={
                                        updatingDispatchUuid === dispatch.public_uuid ||
                                        !selectedStatus ||
                                        currentStatusIsTerminal
                                      }
                                      onClick={() => void handleDispatchStatusUpdate(dispatch)}
                                    >
                                      Update
                                    </Button>
                                  </div>
                                )}
                              </li>
                            );
                          })}
                        </ul>
                      )}
                    </section>

                    <section className="border-t border-[#002D62]/10 pt-6">
                      <h3 className="text-sm font-semibold text-gray-900">
                        Response Timing
                      </h3>
                      {responseTimingLoading ? (
                        <div className="mt-4">
                          <LoadingSkeleton lines={3} />
                        </div>
                      ) : responseTimingError ? (
                        <div className="mt-4 rounded-2xl bg-red-50 p-3 text-sm text-red-700">
                          {responseTimingError}
                        </div>
                      ) : !responseTiming ? (
                        <p className="mt-4 text-sm text-gray-600">
                          Response timing is not available for this incident yet.
                        </p>
                      ) : (
                        <dl className="mt-4 grid gap-4 sm:grid-cols-2">
                          <DetailItem
                            label="Call to Incident"
                            value={formatMinuteValue(responseTiming.call_to_incident_minutes)}
                          />
                          <DetailItem
                            label="Incident to Agency"
                            value={formatMinuteValue(responseTiming.incident_to_agency_minutes)}
                          />
                          <DetailItem
                            label="Agency to Dispatch"
                            value={formatMinuteValue(responseTiming.agency_to_dispatch_minutes)}
                          />
                          <DetailItem
                            label="Dispatch to Arrival"
                            value={formatMinuteValue(responseTiming.dispatch_to_arrival_minutes)}
                          />
                          <DetailItem
                            label="First Agency Joined"
                            value={formatMilestoneValue(responseTiming.first_agency_joined_at)}
                          />
                          <DetailItem
                            label="First Unit Assigned"
                            value={formatMilestoneValue(responseTiming.first_unit_assigned_at)}
                          />
                          <DetailItem
                            label="First Unit Dispatched"
                            value={formatMilestoneValue(responseTiming.first_unit_dispatched_at)}
                          />
                          <DetailItem
                            label="First Unit Arrived"
                            value={formatMilestoneValue(responseTiming.first_unit_arrived_at)}
                          />
                        </dl>
                      )}
                    </section>
                  </CardContent>
                </Card>

                <Card className="shadow-md">
                  <CardHeader>
                    <h2 className="text-lg font-semibold text-[#002D62]">
                      Linked Intake Reports
                    </h2>
                    {currentStatusIsTerminal ? (
                      <p className="mt-1 text-sm text-gray-600">
                        Terminal incidents cannot accept new intake links.
                      </p>
                    ) : null}
                  </CardHeader>
                  <CardContent>
                    {linkSuccess ? (
                      <div className="mb-4 rounded-2xl bg-green-50 p-3 text-sm text-green-700">
                        {linkSuccess}
                      </div>
                    ) : null}
                    {linkedReports.length === 0 ? (
                      <p className="text-sm text-gray-600">
                        No intake reports linked yet.
                      </p>
                    ) : (
                      <ul className="divide-y divide-[#002D62]/10">
                        {linkedReports.map((report) => (
                          <li key={report.intake_public_uuid} className="py-4">
                            <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                              <div className="min-w-0">
                                <div className="flex flex-wrap items-center gap-2">
                                  <span className="rounded-full bg-white px-2.5 py-1 text-xs font-semibold text-[#002D62]">
                                    {report.intake_report_code}
                                  </span>
                                  <Badge tone={report.intake_status}>
                                    {formatBadgeLabel(report.intake_status)}
                                  </Badge>
                                  <span className="rounded-full bg-white px-2.5 py-1 text-xs font-medium text-slate-700">
                                    {formatBadgeLabel(report.link_type)}
                                  </span>
                                </div>
                                <p className="mt-3 break-words text-sm font-medium text-gray-900">
                                  {report.intake_summary}
                                </p>
                                <p className="mt-1 text-xs text-gray-500">
                                  Linked {formatBangladeshTime(report.linked_at)}
                                </p>
                                <p className="mt-1 text-xs text-gray-500">
                                  Location: {formatLocation(report)}
                                </p>
                              </div>
                              <Button
                                type="button"
                                variant="secondary"
                                size="sm"
                                onClick={() =>
                                  router.push(
                                    `/dashboard/dispatcher/intake-reports/${report.intake_public_uuid}`,
                                  )
                                }
                              >
                                Open Intake
                              </Button>
                            </div>
                          </li>
                        ))}
                      </ul>
                    )}
                  </CardContent>
                </Card>

                <Card className="shadow-md">
                <CardHeader>
                  <h2 className="text-lg font-semibold text-[#002D62]">
                    Timeline Preview
                  </h2>
                </CardHeader>
                <CardContent>
                  {timeline.length === 0 ? (
                    <p className="text-sm text-gray-600">
                      No timeline events available.
                    </p>
                  ) : (
                    <ol className="relative space-y-5 border-l border-[#002D62]/20 pl-5">
                      {timeline.map((event) => (
                        <li key={event.id} className="relative">
                          <span className="absolute -left-[1.68rem] mt-1.5 h-3 w-3 rounded-full bg-[#006747] ring-4 ring-zinc-200" />
                          <div className="flex flex-col gap-1">
                            <p className="text-sm font-semibold text-gray-900">
                              {event.event_title}
                            </p>
                            {event.event_description ? (
                              <p className="text-sm leading-6 text-gray-600">
                                {event.event_description}
                              </p>
                            ) : null}
                            <p className="text-xs text-gray-500">
                              {formatBadgeLabel(event.event_type)} |{" "}
                              {formatBangladeshTime(event.event_time)}
                            </p>
                          </div>
                        </li>
                      ))}
                    </ol>
                  )}
                </CardContent>
              </Card>
            </div>

            <aside className="space-y-6 lg:self-start">
              <Card className="shadow-md">
                <CardHeader>
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <h2 className="text-lg font-semibold text-[#002D62]">
                        Recent Intake Reports
                      </h2>
                      <p className="mt-1 text-sm text-gray-600">
                        Expand to review recently reported intake reports.
                      </p>
                    </div>
                    <Button
                      type="button"
                      variant="secondary"
                      size="sm"
                      onClick={() =>
                        setRecentReportsExpanded((expanded) => !expanded)
                      }
                      aria-expanded={recentReportsExpanded}
                      aria-label={
                        recentReportsExpanded
                          ? "Collapse recent intake reports"
                          : "Expand recent intake reports"
                      }
                    >
                      {recentReportsExpanded ? (
                        <ChevronUp className="h-4 w-4" aria-hidden />
                      ) : (
                        <ChevronDown className="h-4 w-4" aria-hidden />
                      )}
                    </Button>
                  </div>
                </CardHeader>

                {recentReportsExpanded ? (
                  <CardContent className="space-y-4">
                    {loadingRecentReports ? (
                      <LoadingSkeleton lines={2} />
                    ) : visibleRecentIntakeReports.length === 0 ? (
                      <EmptyState
                        title="No recent intake reports"
                        description="No unlinked recent intake reports were found."
                      />
                    ) : (
                      <div className="space-y-4 transition-all duration-200 ease-out">
                        {visibleRecentIntakeReports.map((report) => {
                          const isAlreadyLinked =
                            report.has_incident ||
                            linkedReportUuidSet.has(report.public_uuid);

                          return (
                            <div
                              key={report.public_uuid}
                              className="flex flex-col gap-4 rounded-lg border border-gray-200 p-4 sm:flex-row sm:items-center sm:justify-between"
                            >
                              <div className="min-w-0 flex-1">
                                <div className="flex flex-wrap items-center gap-2">
                                  <Badge tone={report.urgency_type}>
                                    {formatBadgeLabel(report.urgency_type)}
                                  </Badge>
                                  <Badge tone={report.category_code}>
                                    {formatBadgeLabel(report.category_code)}
                                  </Badge>
                                  {isAlreadyLinked ? (
                                    <Badge tone="linked_to_incident">
                                      Already linked
                                    </Badge>
                                  ) : null}
                                </div>
                                <p className="mt-1 text-sm text-gray-600">
                                  Reported {formatBangladeshTime(report.reported_at)}
                                </p>
                                <p className="mt-1 truncate text-xs text-gray-500">
                                  Location: {formatRecentReportLocation(report)}
                                </p>
                                <p className="mt-1 truncate text-sm text-gray-500">
                                  {report.summary ||
                                    report.description ||
                                    "No summary available."}
                                </p>
                              </div>
                              <Button
                                type="button"
                                size="sm"
                                onClick={() => {
                                  setLinkIntakeUuid(report.public_uuid);
                                  openLinkModal();
                                }}
                                disabled={
                                  currentStatusIsTerminal ||
                                  isLinkingIntake ||
                                  isAlreadyLinked
                                }
                              >
                                {isAlreadyLinked ? "Already linked" : "Link"}
                              </Button>
                            </div>
                          );
                        })}
                      </div>
                    )}

                    {currentStatusIsTerminal ? (
                      <p className="text-sm text-gray-600">
                        Terminal incidents cannot accept new intake links.
                      </p>
                    ) : null}
                  </CardContent>
                ) : null}
              </Card>

              <Card className="shadow-md">
                <CardHeader>
                  <h2 className="text-lg font-semibold text-[#002D62]">
                    Action Panel
                  </h2>
                  <p className="mt-1 text-sm text-gray-600">
                    Current status:{" "}
                    <span className="font-semibold text-[#002D62]">
                      {formatBadgeLabel(incident.status_code)}
                    </span>
                  </p>
                </CardHeader>
                <CardContent className="space-y-6">
                  <section>
                    <h3 className="text-sm font-semibold text-gray-900">
                      Update Status
                    </h3>
                    <p className="mt-1 text-sm leading-6 text-gray-600">
                      {currentStatusIsTerminal
                        ? "Terminal incidents cannot be changed further."
                        : allowedTransitions.length > 0
                        ? `Available next step${
                            allowedTransitions.length > 1 ? "s" : ""
                          }: ${allowedTransitions
                            .map((status) => formatBadgeLabel(status))
                            .join(", ")}.`
                        : "No status transition is available for this incident."}
                    </p>
                    {statusUpdateError && (
                      <div className="mt-3 rounded-2xl bg-red-50 p-3 text-sm text-red-700">
                        {statusUpdateError}
                      </div>
                    )}
                    {statusUpdateSuccess && (
                      <div className="mt-3 rounded-2xl bg-green-50 p-3 text-sm text-green-700">
                        {statusUpdateSuccess}
                      </div>
                    )}

                    <form
                      onSubmit={(event) => {
                        event.preventDefault();
                        if (!canUpdateStatus || !statusCode) return;
                        setConfirmStatusOpen(true);
                      }}
                      className="mt-4 space-y-4"
                    >
                      <div>
                        <label className={labelClassName}>Next Status</label>
                        <select
                          value={statusCode}
                          onChange={(event) =>
                            handleStatusChange(event.target.value)
                          }
                          className={fieldClassName}
                          disabled={!canUpdateStatus || isUpdatingStatus}
                          required
                        >
                          {allowedTransitions.length === 0 ? (
                            <option value="">No available transitions</option>
                          ) : (
                            allowedTransitions.map((status) => (
                              <option key={status} value={status}>
                                {formatBadgeLabel(status)}
                              </option>
                            ))
                          )}
                        </select>
                      </div>

                      {shouldSendOutcome ? (
                        <div>
                          <label className={labelClassName}>Outcome</label>
                          <select
                            value={outcomeCode}
                            onChange={(event) =>
                              setOutcomeCode(event.target.value)
                            }
                            className={fieldClassName}
                            disabled={!canUpdateStatus || isUpdatingStatus}
                            required
                          >
                            {OUTCOME_OPTIONS.map((outcome) => (
                              <option key={outcome} value={outcome}>
                                {formatBadgeLabel(outcome)}
                              </option>
                            ))}
                          </select>
                        </div>
                      ) : null}

                      <div>
                        <label className={labelClassName}>Status Note</label>
                        <textarea
                          value={statusNote}
                          onChange={(event) => setStatusNote(event.target.value)}
                          className={fieldClassName}
                          rows={3}
                          placeholder="Optional status history note"
                          disabled={!canUpdateStatus || isUpdatingStatus}
                        />
                      </div>

                      <Button
                        type="submit"
                        disabled={!canUpdateStatus || isUpdatingStatus || !statusCode}
                        fullWidth
                      >
                        {isUpdatingStatus ? "Updating..." : "Update Status"}
                      </Button>
                    </form>
                  </section>

                  <section className="border-t border-[#002D62]/10 pt-6">
                    <h3 className="text-sm font-semibold text-gray-900">
                      Add Operator Note
                    </h3>
                    {noteError && (
                      <div className="mt-3 rounded-2xl bg-red-50 p-3 text-sm text-red-700">
                        {noteError}
                      </div>
                    )}
                    {noteSuccess && (
                      <div className="mt-3 rounded-2xl bg-green-50 p-3 text-sm text-green-700">
                        {noteSuccess}
                      </div>
                    )}

                    <form onSubmit={handleNoteSubmit} className="mt-4 space-y-4">
                      <div>
                        <label className={labelClassName}>Title</label>
                        <input
                          value={noteTitle}
                          onChange={(event) => {
                            setNoteTitle(event.target.value);
                            setNoteError(null);
                            setNoteSuccess(null);
                          }}
                          className={fieldClassName}
                          placeholder="Radio check"
                          maxLength={255}
                          disabled={isAddingNote}
                          required
                        />
                      </div>

                      <div>
                        <label className={labelClassName}>Event Time</label>
                        <input
                          type="datetime-local"
                          value={noteEventTime}
                          onChange={(event) =>
                            setNoteEventTime(event.target.value)
                          }
                          className={fieldClassName}
                          disabled={isAddingNote}
                        />
                      </div>

                      <div>
                        <label className={labelClassName}>Description</label>
                        <textarea
                          value={noteDescription}
                          onChange={(event) =>
                            setNoteDescription(event.target.value)
                          }
                          className={fieldClassName}
                          rows={3}
                          placeholder="Optional body"
                          disabled={isAddingNote}
                        />
                      </div>

                      <Button
                        type="submit"
                        disabled={isAddingNote || !noteTitle.trim()}
                        fullWidth
                      >
                        {isAddingNote ? "Adding..." : "Add Note"}
                      </Button>
                    </form>
                  </section>
                </CardContent>
              </Card>
            </aside>
          </div>
        ) : null}
      </div>
    </DashboardLayout>
  );
}
