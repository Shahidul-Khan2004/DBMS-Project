"use client";

import { type FormEvent, useCallback, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { clearAuthSession, getValidAccessToken } from "@/lib/auth-store";

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
  reported_at: string;
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
    event_time?: string;
    created_at?: string;
  };
}

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

const STATUS_OPTIONS = [
  "reported",
  "classified",
  "in_progress",
  "resolved",
  "closed",
  "cancelled",
];

const TERMINAL_STATUSES = ["resolved", "closed", "cancelled"];

const OUTCOME_OPTIONS = [
  "resolved",
  "false_alarm",
  "duplicate_incident",
  "cancelled",
  "transferred",
  "unresolved",
];

const labelClassName = "block text-sm font-medium text-gray-700";
const fieldClassName =
  "mt-1 w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-gray-900 placeholder-gray-400 disabled:cursor-not-allowed disabled:bg-gray-100 disabled:text-gray-500";

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
  const [statusCode, setStatusCode] = useState("in_progress");
  const [note, setNote] = useState("");
  const [outcomeCode, setOutcomeCode] = useState("resolved");
  const [isUpdatingStatus, setIsUpdatingStatus] = useState(false);
  const [statusUpdateError, setStatusUpdateError] = useState<string | null>(null);
  const [statusUpdateSuccess, setStatusUpdateSuccess] = useState<string | null>(
    null,
  );
  const [noteTitle, setNoteTitle] = useState("");
  const [noteDescription, setNoteDescription] = useState("");
  const [noteEventTime, setNoteEventTime] = useState("");
  const [isAddingNote, setIsAddingNote] = useState(false);
  const [noteError, setNoteError] = useState<string | null>(null);
  const [noteSuccess, setNoteSuccess] = useState<string | null>(null);

  const redirectToLogin = useCallback(() => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/auth/login");
  }, [router]);

  const loadIncident = useCallback(async () => {
    const accessToken = getValidAccessToken();
    if (!accessToken) {
      redirectToLogin();
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `${API_BASE}/operations/incidents/${incidentPublicUuid}`,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        }
      );

      const data = (await response.json().catch(() => ({}))) as
        | IncidentResponse
        | { error?: { message?: string }; message?: string };

      if (!response.ok) {
        let errMsg = "Could not load incident.";

        if ("error" in data && data.error?.message) {
          errMsg = data.error.message;
        } else if ("message" in data && typeof data.message === "string") {
          errMsg = data.message;
        }

        setError(errMsg);
        setIncident(null);
        setLinkedReports([]);
        setTimeline([]);
        return;
      }

      const responseData = data as IncidentResponse;
      setIncident(responseData.incident);
      setLinkedReports(responseData.linked_intake_reports);
      setTimeline(responseData.timeline_preview);
    } catch {
      setError("Unexpected error while loading incident.");
      setIncident(null);
      setLinkedReports([]);
      setTimeline([]);
    } finally {
      setLoading(false);
    }
  }, [incidentPublicUuid, redirectToLogin]);

  useEffect(() => {
    const sessionUser = sessionStorage.getItem("loggedInUser");
    const accessToken = getValidAccessToken();

    if (!sessionUser || !accessToken) {
      redirectToLogin();
      return;
    }

    try {
      JSON.parse(sessionUser);
    } catch {
      redirectToLogin();
      return;
    }

    setIsLoadingSession(false);
  }, [redirectToLogin]);

  useEffect(() => {
    if (isLoadingSession || !incidentPublicUuid) return;
    void loadIncident();
  }, [isLoadingSession, incidentPublicUuid, loadIncident]);

  useEffect(() => {
    if (!incident) return;

    setStatusCode(incident.status_code);
    setOutcomeCode(incident.outcome_code ?? "resolved");
  }, [incident]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  const handleStatusChange = (nextStatusCode: string) => {
    setStatusCode(nextStatusCode);
    setStatusUpdateError(null);
    setStatusUpdateSuccess(null);

    if (!TERMINAL_STATUSES.includes(nextStatusCode)) {
      setOutcomeCode("resolved");
    }
  };

  const getBackendErrorMessage = (data: unknown, fallback: string) => {
    if (!data || typeof data !== "object") return fallback;

    const responseData = data as {
      code?: string;
      message?: string;
      error?: { code?: string; message?: string };
    };

    return (
      responseData.error?.code ||
      responseData.code ||
      responseData.error?.message ||
      responseData.message ||
      fallback
    );
  };

  const handleStatusSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!incident) return;

    const accessToken = getValidAccessToken();
    if (!accessToken) {
      redirectToLogin();
      return;
    }

    const shouldSendOutcome = TERMINAL_STATUSES.includes(statusCode);

    setIsUpdatingStatus(true);
    setStatusUpdateError(null);
    setStatusUpdateSuccess(null);

    try {
      const response = await fetch(
        `${API_BASE}/operations/incidents/${incidentPublicUuid}/status`,
        {
          method: "PATCH",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${accessToken}`,
          },
          body: JSON.stringify({
            statusCode,
            note,
            ...(shouldSendOutcome ? { outcomeCode } : {}),
          }),
        },
      );

      const data = (await response.json().catch(() => ({}))) as
        | StatusUpdateResponse
        | {
            code?: string;
            message?: string;
            error?: { code?: string; message?: string };
      };

      if (!response.ok) {
        setStatusUpdateError(getBackendErrorMessage(data, "Could not update status."));
        return;
      }

      const responseData = data as StatusUpdateResponse;
      setIncident(responseData.incident);
      setNote("");
      setStatusUpdateSuccess(responseData.message ?? "Incident status updated.");
      await loadIncident();
    } catch {
      setStatusUpdateError("Unexpected error while updating incident status.");
    } finally {
      setIsUpdatingStatus(false);
    }
  };

  const handleNoteSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();

    if (!incident || !noteTitle.trim()) return;

    const accessToken = getValidAccessToken();
    if (!accessToken) {
      redirectToLogin();
      return;
    }

    setIsAddingNote(true);
    setNoteError(null);
    setNoteSuccess(null);

    try {
      const response = await fetch(
        `${API_BASE}/operations/incidents/${incidentPublicUuid}/notes`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${accessToken}`,
          },
          body: JSON.stringify({
            title: noteTitle.trim(),
            description: noteDescription.trim() || undefined,
            eventTime: noteEventTime
              ? new Date(noteEventTime).toISOString()
              : undefined,
          }),
        },
      );

      const data = (await response.json().catch(() => ({}))) as
        | NoteResponse
        | {
            code?: string;
            message?: string;
            error?: { code?: string; message?: string };
          };

      if (!response.ok) {
        setNoteError(getBackendErrorMessage(data, "Could not add operator note."));
        return;
      }

      const responseData = data as NoteResponse;
      const nowIso = new Date().toISOString();
      setTimeline((currentTimeline) => [
        {
          ...responseData.note,
          event_time: responseData.note.event_time ?? nowIso,
          created_at: responseData.note.created_at ?? nowIso,
        },
        ...currentTimeline,
      ]);
      setNoteTitle("");
      setNoteDescription("");
      setNoteEventTime("");
      setNoteSuccess(responseData.message ?? "Operator note added.");
      await loadIncident();
    } catch {
      setNoteError("Unexpected error while adding operator note.");
    } finally {
      setIsAddingNote(false);
    }
  };

  const formatDate = (iso: string) => {
    if (!iso) return "—";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString();
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "reported":
        return "bg-red-100 text-red-800";
      case "classified":
        return "bg-yellow-100 text-yellow-800";
      case "in_progress":
        return "bg-blue-100 text-blue-800";
      case "resolved":
        return "bg-green-100 text-green-800";
      case "closed":
        return "bg-gray-100 text-gray-800";
      case "cancelled":
        return "bg-gray-100 text-gray-800";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-red-100 text-red-800";
      case "high":
        return "bg-orange-100 text-orange-800";
      case "medium":
        return "bg-yellow-100 text-yellow-800";
      case "low":
        return "bg-green-100 text-green-800";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  const isTerminalStatus = incident
    ? TERMINAL_STATUSES.includes(incident.status_code)
    : false;
  const canSetOutcome = TERMINAL_STATUSES.includes(statusCode);

  if (isLoadingSession) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        Loading...
      </div>
    );
  }

  return (
    <DashboardLayout
      title="Incident Details"
      subtitle={`Incident ${incident?.incident_code || incidentPublicUuid}`}
      onLogout={handleLogout}
    >
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <Button
            type="button"
            variant="secondary"
            onClick={() => router.push("/dashboard/dispatcher/incidents")}
          >
            ← Back to Incidents
          </Button>
          <Button
            type="button"
            variant="secondary"
            onClick={() => void loadIncident()}
            disabled={loading}
          >
            {loading ? "Loading..." : "Refresh"}
          </Button>
        </div>

        {error && (
          <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800">
            <p>{error}</p>
          </div>
        )}

        {loading && !incident ? (
          <div className="text-center text-sm text-gray-500">Loading incident...</div>
        ) : incident ? (
          <div className="grid gap-6 md:grid-cols-2">
            <Card className="shadow-md">
              <CardHeader>
                <h2 className="text-lg font-semibold text-gray-900">
                  Incident Information
                </h2>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <label className="text-sm font-medium text-gray-700">
                    Incident Code
                  </label>
                  <p className="mt-1 text-sm text-gray-900">{incident.incident_code}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-700">
                    Status
                  </label>
                  <p className="mt-1">
                    <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${getStatusColor(incident.status_code)}`}>
                      {incident.status_code}
                    </span>
                  </p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-700">
                    Severity
                  </label>
                  <p className="mt-1">
                    <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${getSeverityColor(incident.severity_code)}`}>
                      {incident.severity_code}
                    </span>
                  </p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-700">
                    Category
                  </label>
                  <p className="mt-1 text-sm text-gray-900">{incident.category_code}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-700">
                    Origin Type
                  </label>
                  <p className="mt-1 text-sm text-gray-900">{incident.origin_type}</p>
                </div>
                {incident.outcome_code && (
                  <div>
                    <label className="text-sm font-medium text-gray-700">
                      Outcome
                    </label>
                    <p className="mt-1 text-sm text-gray-900">{incident.outcome_code}</p>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="shadow-md">
              <CardHeader>
                <h2 className="text-lg font-semibold text-gray-900">
                  Incident Content
                </h2>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <label className="text-sm font-medium text-gray-700">
                    Title
                  </label>
                  <p className="mt-1 text-sm text-gray-900">{incident.title}</p>
                </div>
                {incident.description && (
                  <div>
                    <label className="text-sm font-medium text-gray-700">
                      Description
                    </label>
                    <p className="mt-1 text-sm text-gray-900 whitespace-pre-wrap">
                      {incident.description}
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="shadow-md md:col-span-2">
              <CardHeader>
                <h2 className="text-lg font-semibold text-gray-900">
                  Update Incident Status
                </h2>
                {isTerminalStatus && (
                  <p className="mt-1 text-sm text-gray-500">
                    Terminal incidents cannot be changed further.
                  </p>
                )}
              </CardHeader>
              <CardContent>
                {statusUpdateError && (
                  <div className="mb-4 rounded-md bg-red-50 p-3 text-sm text-red-700">
                    {statusUpdateError}
                  </div>
                )}

                {statusUpdateSuccess && (
                  <div className="mb-4 rounded-md bg-green-50 p-3 text-sm text-green-700">
                    {statusUpdateSuccess}
                  </div>
                )}

                <form onSubmit={handleStatusSubmit} className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-2">
                    <div>
                      <label className={labelClassName}>Status</label>
                      <select
                        value={statusCode}
                        onChange={(event) =>
                          handleStatusChange(event.target.value)
                        }
                        className={fieldClassName}
                        disabled={isTerminalStatus || isUpdatingStatus}
                        required
                      >
                        {STATUS_OPTIONS.map((status) => (
                          <option key={status} value={status}>
                            {status}
                          </option>
                        ))}
                      </select>
                    </div>

                    {canSetOutcome && (
                      <div>
                        <label className={labelClassName}>Outcome</label>
                        <select
                          value={outcomeCode}
                          onChange={(event) =>
                            setOutcomeCode(event.target.value)
                          }
                          className={fieldClassName}
                          disabled={isTerminalStatus || isUpdatingStatus}
                          required
                        >
                          {OUTCOME_OPTIONS.map((outcome) => (
                            <option key={outcome} value={outcome}>
                              {outcome}
                            </option>
                          ))}
                        </select>
                      </div>
                    )}
                  </div>

                  <div>
                    <label className={labelClassName}>Note</label>
                    <textarea
                      value={note}
                      onChange={(event) => setNote(event.target.value)}
                      className={fieldClassName}
                      rows={4}
                      placeholder="Optional note stored in status history"
                      disabled={isTerminalStatus || isUpdatingStatus}
                    />
                  </div>

                  <Button
                    type="submit"
                    disabled={isTerminalStatus || isUpdatingStatus}
                  >
                    {isUpdatingStatus ? "Updating..." : "Update Status"}
                  </Button>
                </form>
              </CardContent>
            </Card>

            <Card className="shadow-md md:col-span-2">
              <CardHeader>
                <h2 className="text-lg font-semibold text-gray-900">
                  Add Operator Note
                </h2>
              </CardHeader>
              <CardContent>
                {noteError && (
                  <div className="mb-4 rounded-md bg-red-50 p-3 text-sm text-red-700">
                    {noteError}
                  </div>
                )}

                {noteSuccess && (
                  <div className="mb-4 rounded-md bg-green-50 p-3 text-sm text-green-700">
                    {noteSuccess}
                  </div>
                )}

                <form onSubmit={handleNoteSubmit} className="space-y-4">
                  <div className="grid gap-4 md:grid-cols-2">
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
                        onChange={(event) => setNoteEventTime(event.target.value)}
                        className={fieldClassName}
                        disabled={isAddingNote}
                      />
                    </div>
                  </div>

                  <div>
                    <label className={labelClassName}>Description</label>
                    <textarea
                      value={noteDescription}
                      onChange={(event) => setNoteDescription(event.target.value)}
                      className={fieldClassName}
                      rows={4}
                      placeholder="Optional body"
                      disabled={isAddingNote}
                    />
                  </div>

                  <Button type="submit" disabled={isAddingNote || !noteTitle.trim()}>
                    {isAddingNote ? "Adding..." : "Add Note"}
                  </Button>
                </form>
              </CardContent>
            </Card>

            <Card className="shadow-md md:col-span-2">
              <CardHeader>
                <h2 className="text-lg font-semibold text-gray-900">
                  Timestamps
                </h2>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid gap-4 md:grid-cols-4">
                  <div>
                    <label className="text-sm font-medium text-gray-700">
                      Reported At
                    </label>
                    <p className="mt-1 text-sm text-gray-900">
                      {formatDate(incident.reported_at)}
                    </p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-700">
                      Created At
                    </label>
                    <p className="mt-1 text-sm text-gray-900">
                      {formatDate(incident.created_at)}
                    </p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-700">
                      Updated At
                    </label>
                    <p className="mt-1 text-sm text-gray-900">
                      {formatDate(incident.updated_at)}
                    </p>
                  </div>
                  <div>
                    <label className="text-sm font-medium text-gray-700">
                      Resolved At
                    </label>
                    <p className="mt-1 text-sm text-gray-900">
                      {incident.resolved_at ? formatDate(incident.resolved_at) : "—"}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>

            {linkedReports.length > 0 && (
              <Card className="shadow-md md:col-span-2">
                <CardHeader>
                  <h2 className="text-lg font-semibold text-gray-900">
                    Linked Intake Reports
                  </h2>
                </CardHeader>
                <CardContent>
                  <ul className="divide-y divide-gray-100">
                    {linkedReports.map((report) => (
                      <li key={report.intake_public_uuid} className="py-3">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="font-medium text-gray-900">
                              {report.intake_report_code}
                            </p>
                            <p className="text-sm text-gray-600">
                              {report.intake_summary}
                            </p>
                            <p className="text-xs text-gray-500">
                              Status: {report.intake_status} | Linked: {formatDate(report.linked_at)}
                            </p>
                          </div>
                          <Button
                            type="button"
                            variant="secondary"
                            size="sm"
                            onClick={() =>
                              router.push(
                                `/dashboard/dispatcher/intake-reports/${report.intake_public_uuid}`
                              )
                            }
                          >
                            View Report
                          </Button>
                        </div>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            )}

            {timeline.length > 0 && (
              <Card className="shadow-md md:col-span-2">
                <CardHeader>
                  <h2 className="text-lg font-semibold text-gray-900">
                    Timeline (Recent Events)
                  </h2>
                </CardHeader>
                <CardContent>
                  <ul className="divide-y divide-gray-100">
                    {timeline.map((event) => (
                      <li key={event.id} className="py-3">
                        <div className="flex items-start justify-between">
                          <div className="min-w-0 flex-1">
                            <p className="font-medium text-gray-900">
                              {event.event_title}
                            </p>
                            {event.event_description && (
                              <p className="text-sm text-gray-600 mt-1">
                                {event.event_description}
                              </p>
                            )}
                            <p className="text-xs text-gray-500 mt-1">
                              {event.event_type} • {formatDate(event.event_time)}
                            </p>
                          </div>
                        </div>
                      </li>
                    ))}
                  </ul>
                </CardContent>
              </Card>
            )}
          </div>
        ) : null}
      </div>
    </DashboardLayout>
  );
}
