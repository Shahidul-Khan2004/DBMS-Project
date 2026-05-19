"use client";

import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { useParams, useRouter } from "next/navigation";
import { AlertTriangle, FileText, MessageSquare, RefreshCw, ShieldCheck } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { EmptyState, MessageBanner, PageLoading } from "@/components/ui/StatusState";
import { ApiError, apiGet, apiPatch, apiPost } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { formatBangladeshTime } from "@/lib/datetime";
import { getOperationsServiceCaseMessages } from "@/lib/service-case-api";
import {
  getServiceCaseStatusLabel,
  isServiceCaseEscalated,
} from "@/lib/service-case-status";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type {
  OperationsServiceCase,
  ServiceCaseAssignment,
  ServiceCaseDetailResponse,
  ServiceCaseMessageResult,
  ServiceCaseResolution,
  ServiceCaseStatusHistoryItem,
} from "@/types/service-case";

function DetailRow({ label, value }: { label: string; value: string | null }) {
  return (
    <div>
      <p className="text-sm font-medium text-gray-600">{label}</p>
      <p className="mt-1 break-all text-sm text-gray-900">{value || "-"}</p>
    </div>
  );
}

function parseMessageBody(message: ServiceCaseMessageResult) {
  if (message.subject !== undefined || message.body !== undefined) {
    const subject = message.subject?.trim();
    const body = message.body?.trim();

    return {
      subject: subject || "Message",
      body: body || null,
    };
  }

  const rawBody = message.message_body?.trim();
  if (!rawBody) {
    return {
      subject: "Message",
      body: null,
    };
  }

  const [subjectLine, ...rest] = rawBody.split(/\r?\n\r?\n/);
  const subject = subjectLine.replace(/^Subject:\s*/i, "").trim();
  return {
    subject: subject || "Message",
    body: rest.join("\n\n").trim() || null,
  };
}

const terminalStatuses = new Set(["resolved", "closed", "cancelled", "escalated_to_emergency"]);

type EscalateResponse = {
  message?: string;
  incident?: {
    public_uuid?: string;
    incident_code?: string;
    title?: string;
    origin_type?: string;
  };
};

function getMessageLabel(message: ServiceCaseMessageResult) {
  if (message.message_type === "admin_reply") return "Dispatcher/Admin";
  if (message.message_type === "user_message") return "Citizen";
  if (message.message_type === "system_note") return "System";
  return formatBadgeLabel(message.message_type);
}

export default function DispatcherServiceCaseDetailPage() {
  const router = useRouter();
  const params = useParams();
  const publicUuid = params.publicUuid as string;
  const isChecking = useAuthGuard(["dispatcher", "system_admin"]);
  const [serviceCase, setServiceCase] = useState<OperationsServiceCase | null>(null);
  const [statusHistory, setStatusHistory] = useState<ServiceCaseStatusHistoryItem[]>([]);
  const [messages, setMessages] = useState<ServiceCaseMessageResult[]>([]);
  const [assignments, setAssignments] = useState<ServiceCaseAssignment[]>([]);
  const [resolution, setResolution] = useState<ServiceCaseResolution | null>(null);
  const [loading, setLoading] = useState(true);
  const [messagesLoading, setMessagesLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState(false);
  const [statusCode, setStatusCode] = useState("");
  const [statusNote, setStatusNote] = useState("");
  const [messageTitle, setMessageTitle] = useState("");
  const [messageDescription, setMessageDescription] = useState("");
  const [assignTo, setAssignTo] = useState("");
  const [assignNote, setAssignNote] = useState("");
  const [resolutionType, setResolutionType] = useState("advice_given");
  const [resolutionText, setResolutionText] = useState("");
  const [recommendedFacilityId, setRecommendedFacilityId] = useState("");
  const [escalationReason, setEscalationReason] = useState("");
  const [escalatedIncidentPublicUuid, setEscalatedIncidentPublicUuid] = useState("");

  const isTerminal = useMemo(
    () => serviceCase ? terminalStatuses.has(serviceCase.status_code || "") : false,
    [serviceCase],
  );
  const isEscalated = isServiceCaseEscalated(serviceCase?.status_code);
  const canSendDispatcherMessage = serviceCase?.status_code === "under_review";
  const canEscalateToEmergency =
    !isTerminal && Boolean(serviceCase?.intake_public_uuid);
  const showEscalationPanel = canEscalateToEmergency;
  const linkedIncidentPublicUuid =
    escalatedIncidentPublicUuid || serviceCase?.linked_incident_public_uuid || "";

  const statusOptions = useMemo(() => {
    switch (serviceCase?.status_code) {
      case "submitted":
        return [
          { value: "under_review", label: "Under Review" },
          { value: "cancelled", label: "Cancelled" },
        ];
      case "under_review":
        return [
          { value: "awaiting_user_response", label: "Awaiting User Response" },
          { value: "closed", label: "Closed" },
          { value: "cancelled", label: "Cancelled" },
        ];
      case "awaiting_user_response":
        return [
          { value: "under_review", label: "Under Review" },
          { value: "closed", label: "Closed" },
          { value: "cancelled", label: "Cancelled" },
        ];
      default:
        return [];
    }
  }, [serviceCase?.status_code]);

  const loadMessages = useCallback(async () => {
    setMessagesLoading(true);

    try {
      const data = await getOperationsServiceCaseMessages(publicUuid);
      setMessages(data.messages ?? []);
    } catch (err) {
      setFormError(
        err instanceof Error
          ? err.message
          : "Unexpected error while loading service case messages.",
      );
      setMessages([]);
    } finally {
      setMessagesLoading(false);
    }
  }, [publicUuid]);

  const loadServiceCaseDetail = useCallback(async () => {
    setLoading(true);
    setError(null);
    setSuccessMessage(null);

    try {
      const data = await apiGet<ServiceCaseDetailResponse>(
        `/operations/service-cases/${publicUuid}`,
      );
      setServiceCase(data.service_case);
      setStatusHistory(data.status_history ?? []);
      setAssignments(data.assignments ?? []);
      setResolution(data.resolution ?? null);
      setStatusCode("");
      setStatusNote("");
      setAssignTo("");
      setAssignNote("");
      setMessageTitle("");
      setMessageDescription("");
      setResolutionText("");
      setRecommendedFacilityId("");
      setEscalationReason("");
      setEscalatedIncidentPublicUuid(
        data.service_case.linked_incident_public_uuid ?? "",
      );
      setFormError(null);
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Unexpected error while loading service case details.",
      );
    } finally {
      setLoading(false);
    }
  }, [publicUuid]);

  const loadServiceCasePage = useCallback(async () => {
    await loadServiceCaseDetail();
    await loadMessages();
  }, [loadMessages, loadServiceCaseDetail]);

  useEffect(() => {
    if (isChecking) return;
    void loadServiceCasePage();
  }, [isChecking, loadServiceCasePage]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  async function refreshCase() {
    await loadServiceCasePage();
  }

  async function handleUpdateStatus(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);
    setSuccessMessage(null);

    if (!statusCode) {
      setFormError("Select a new status to continue.");
      return;
    }

    setActionLoading(true);
    try {
      await apiPatch<ServiceCaseDetailResponse>(
        `/operations/service-cases/${publicUuid}/status`,
        {
          statusCode,
          note: statusNote.trim() || undefined,
        },
      );
      setSuccessMessage("Service case status updated.");
      await loadServiceCasePage();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : err instanceof Error ? err.message : "Could not update status.";
      setFormError(message);
    } finally {
      setActionLoading(false);
    }
  }

  async function handleSendMessage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);
    setSuccessMessage(null);

    const nextTitle = messageTitle.trim() || "Dispatcher reply";
    const nextDescription = messageDescription.trim();

    if (!nextDescription && !messageTitle.trim()) {
      setFormError("Write a message before sending.");
      return;
    }

    if (!canSendDispatcherMessage) {
      setFormError("Dispatcher messages can only be sent while the case is under review.");
      return;
    }

    setActionLoading(true);
    try {
      await apiPost(`/operations/service-cases/${publicUuid}/messages`, {
        title: nextTitle,
        description: nextDescription || undefined,
      });
      setSuccessMessage("Dispatcher response recorded.");
      await loadServiceCasePage();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : err instanceof Error ? err.message : "Could not send message.";
      setFormError(message);
    } finally {
      setActionLoading(false);
    }
  }

  async function handleAssign(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);
    setSuccessMessage(null);

    if (!assignTo.trim()) {
      setFormError("Assignee public UUID is required.");
      return;
    }

    setActionLoading(true);
    try {
      await apiPost(`/operations/service-cases/${publicUuid}/assignments`, {
        assignedToUserPublicUuid: assignTo.trim(),
        note: assignNote.trim() || undefined,
      });
      setSuccessMessage("Service case assigned.");
      await loadServiceCasePage();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : err instanceof Error ? err.message : "Could not assign service case.";
      setFormError(message);
    } finally {
      setActionLoading(false);
    }
  }

  async function handleResolve(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);
    setSuccessMessage(null);

    if (!resolutionText.trim()) {
      setFormError("Resolution narrative is required.");
      return;
    }

    setActionLoading(true);
    try {
      await apiPost<ServiceCaseDetailResponse>(
        `/operations/service-cases/${publicUuid}/resolve`,
        {
          resolutionType,
          resolutionText: resolutionText.trim(),
          recommendedFacilityId: recommendedFacilityId.trim()
            ? Number(recommendedFacilityId.trim())
            : undefined,
        },
      );
      setSuccessMessage("Service case resolved.");
      await loadServiceCasePage();
    } catch (err) {
      const message = err instanceof ApiError ? err.message : err instanceof Error ? err.message : "Could not resolve service case.";
      setFormError(message);
    } finally {
      setActionLoading(false);
    }
  }

  async function handleEscalate(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setFormError(null);
    setSuccessMessage(null);

    if (!escalationReason.trim()) {
      setFormError("Escalation reason is required.");
      return;
    }

    if (!serviceCase?.intake_public_uuid) {
      setFormError("Escalation target is not available.");
      return;
    }

    setActionLoading(true);
    try {
      const data = await apiPost<EscalateResponse>(`/intake/reports/${serviceCase.intake_public_uuid}/escalate`, {
        escalationReason: escalationReason.trim(),
        severityCode: "medium",
      });
      const nextIncidentPublicUuid = data.incident?.public_uuid ?? "";
      if (nextIncidentPublicUuid) {
        router.push(`/dashboard/dispatcher/incidents/${nextIncidentPublicUuid}`);
        return;
      }
      await loadServiceCasePage();
      setEscalatedIncidentPublicUuid("");
      setSuccessMessage(data.message ?? "Service case escalated to emergency incident.");
    } catch (err) {
      const message = err instanceof ApiError ? err.message : err instanceof Error ? err.message : "Could not escalate service case.";
      setFormError(message);
    } finally {
      setActionLoading(false);
    }
  }

  if (isChecking) {
    return <PageLoading label="Loading service case details" />;
  }

  return (
    <DashboardLayout
      title="Service Case Detail"
      subtitle={`Case ${serviceCase?.case_code ?? publicUuid}`}
      onLogout={handleLogout}
    >
      <div className="space-y-6">
        <div className="flex flex-wrap gap-3">
          <Button
            type="button"
            variant="secondary"
            onClick={() => router.push("/dashboard/dispatcher/service-cases")}
          >
            Back to Service Cases
          </Button>
          <Button type="button" variant="secondary" onClick={refreshCase}>
            <RefreshCw className="h-4 w-4" aria-hidden />
            Refresh
          </Button>
        </div>

        {error && <ErrorAlert message={error} />}
        {formError && <ErrorAlert message={formError} />}
        {successMessage && (
          <MessageBanner tone="success">{successMessage}</MessageBanner>
        )}
        {isEscalated ? (
          <MessageBanner tone="info">
            This service case has been escalated to an emergency incident.
          </MessageBanner>
        ) : null}
        {linkedIncidentPublicUuid ? (
          <div>
            <Button
              type="button"
              onClick={() =>
                router.push(
                  `/dashboard/dispatcher/incidents/${linkedIncidentPublicUuid}`,
                )
              }
            >
              Open Emergency Incident
            </Button>
          </div>
        ) : isEscalated ? (
          <p className="text-sm text-gray-600">
            The current service case response does not include the linked emergency incident public UUID.
          </p>
        ) : null}

        <div className={`grid items-start gap-6 ${showEscalationPanel ? "xl:grid-cols-2" : "xl:grid-cols-1"}`}>
          <Card className="shadow-md">
            <CardHeader className="py-4">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#002D62] text-white">
                  <FileText className="h-5 w-5" aria-hidden />
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-[#002D62]">
                    Service Case Snapshot
                  </h2>
                  <p className="mt-1 text-sm text-gray-600">
                    Current case details and workflow state.
                  </p>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {loading ? (
                <LoadingSkeleton lines={6} />
              ) : !serviceCase ? (
                <EmptyState
                  title="Service case not found"
                  description="The requested service case could not be loaded."
                />
              ) : (
                <div className="space-y-4">
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                    <div>
                      <p className="text-xs font-bold uppercase tracking-wide text-gray-600">
                        {serviceCase.case_code}
                      </p>
                      <h3 className="mt-1 text-lg font-semibold text-gray-900">
                        {serviceCase.title}
                      </h3>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      <Badge tone={serviceCase.status_code}>
                        {getServiceCaseStatusLabel(serviceCase.status_code)}
                      </Badge>
                      <Badge tone={serviceCase.priority_level}>
                        {formatBadgeLabel(serviceCase.priority_level)}
                      </Badge>
                    </div>
                  </div>

                  <p className="whitespace-pre-wrap text-sm leading-6 text-gray-700">
                    {serviceCase.description || "No description provided."}
                  </p>

                  <dl className="grid gap-3 sm:grid-cols-2">
                    <DetailRow label="Status" value={getServiceCaseStatusLabel(serviceCase.status_code)} />
                    <DetailRow label="Priority" value={formatBadgeLabel(serviceCase.priority_level)} />
                    <DetailRow label="Category" value={formatBadgeLabel(serviceCase.category_code)} />
                    <DetailRow label="Intake Report" value={serviceCase.intake_report_code} />
                    <DetailRow label="Assigned To" value={serviceCase.assigned_to_user_public_uuid || "Unassigned"} />
                    <DetailRow label="Last Updated" value={formatBangladeshTime(serviceCase.last_updated)} />
                    <DetailRow label="Created At" value={formatBangladeshTime(serviceCase.created_at)} />
                    <DetailRow label="Public UUID" value={serviceCase.public_uuid} />
                  </dl>
                </div>
              )}
            </CardContent>
          </Card>

          {canEscalateToEmergency ? (
            <Card className="shadow-md">
              <CardHeader className="py-4">
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#B71C1C] text-white">
                    <AlertTriangle className="h-5 w-5" aria-hidden />
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-[#002D62]">Escalate to Emergency</h2>
                    <p className="mt-1 text-sm text-gray-600">
                      Create an emergency incident from this service case.
                    </p>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleEscalate} className="space-y-4">
                  <div>
                    <label htmlFor="service-case-escalation-reason" className="block text-sm font-medium text-gray-700">Escalation Reason</label>
                    <textarea
                      id="service-case-escalation-reason"
                      value={escalationReason}
                      onChange={(event) => setEscalationReason(event.target.value)}
                      className="mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                      rows={4}
                      placeholder="Why is escalation required?"
                      required
                    />
                  </div>
                  <div className="flex flex-wrap gap-3">
                    <Button type="submit" isLoading={actionLoading}>
                      Escalate Case
                    </Button>
                  </div>
                </form>
              </CardContent>
            </Card>
          ) : null}
        </div>

        {!loading && serviceCase ? (
          <div className="grid gap-6 xl:grid-cols-2">
            <Card className="shadow-md">
              <CardHeader>
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#002D62] text-white">
                    <MessageSquare className="h-5 w-5" aria-hidden />
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-[#002D62]">Messages</h2>
                    <p className="mt-1 text-sm text-gray-600">
                      Recent case messages from the reporter and operations team.
                    </p>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                {messagesLoading ? (
                  <LoadingSkeleton lines={4} />
                ) : messages.length === 0 ? (
                  <p className="text-sm text-gray-600">No messages recorded yet.</p>
                ) : (
                  <ul className="space-y-4">
                    {messages.map((message) => {
                      const parsed = parseMessageBody(message);
                      return (
                        <li key={message.id} className="rounded-2xl border border-[#002D62]/10 bg-white p-4">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div>
                              <div className="flex flex-wrap items-center gap-2">
                                <p className="text-xs font-bold uppercase tracking-wide text-[#006747]">
                                  {getMessageLabel(message)}
                                </p>
                                {message.is_internal === true ? (
                                  <span className="rounded-full bg-amber-50 px-2 py-0.5 text-xs font-semibold text-amber-700">
                                    Internal
                                  </span>
                                ) : null}
                              </div>
                              <p className="mt-1 text-sm font-semibold text-gray-900">
                                {parsed.subject}
                              </p>
                              {message.sender?.full_name ? (
                                <p className="mt-1 text-xs text-gray-500">
                                  Sender: {message.sender.full_name}
                                </p>
                              ) : null}
                            </div>
                            <span className="text-xs text-gray-500">{formatBangladeshTime(message.created_at)}</span>
                          </div>
                          {parsed.body ? (
                            <p className="mt-3 text-sm leading-6 text-gray-700 whitespace-pre-wrap">
                              {parsed.body}
                            </p>
                          ) : (
                            <p className="mt-3 text-sm text-gray-500">
                              No details provided.
                            </p>
                          )}
                        </li>
                      );
                    })}
                  </ul>
                )}
              </CardContent>
            </Card>

            <Card className="shadow-md">
              <CardHeader>
                <div className="flex items-center gap-3">
                  <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#002D62] text-white">
                    <ShieldCheck className="h-5 w-5" aria-hidden />
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-[#002D62]">Status History</h2>
                    <p className="mt-1 text-sm text-gray-600">
                      Track how this case moved through the workflow.
                    </p>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                {statusHistory.length === 0 ? (
                  <p className="text-sm text-gray-600">No status history available.</p>
                ) : (
                  <ul className="space-y-4">
                    {statusHistory.map((item, index) => (
                      <li
                        key={`${item.changed_at}-${index}`}
                        className="rounded-2xl border border-[#002D62]/10 bg-white p-4"
                      >
                        <p className="text-sm font-semibold text-gray-900">
                          {formatBadgeLabel(item.status_code)}
                        </p>
                        <p className="mt-1 text-sm text-gray-600">
                          {formatBangladeshTime(item.changed_at)}
                        </p>
                        <p className="mt-2 text-sm text-gray-700">
                          {item.note || "No note provided."}
                        </p>
                        {item.changed_by ? (
                          <p className="mt-2 text-xs text-gray-500">
                            Updated by{" "}
                            {item.changed_by.full_name ||
                              item.changed_by.public_uuid}
                            {item.changed_by.actor_kind
                              ? ` (${item.changed_by.actor_kind})`
                              : ""}
                          </p>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                )}
              </CardContent>
            </Card>
          </div>
        ) : null}

        {!loading && serviceCase ? (
          <div className="space-y-6">
            {!isTerminal && statusOptions.length > 0 ? (
              <Card className="shadow-md">
                <CardHeader>
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#002D62] text-white">
                      <AlertTriangle className="h-5 w-5" aria-hidden />
                    </div>
                    <div>
                      <h2 className="text-lg font-semibold text-[#002D62]">Update Status</h2>
                      <p className="mt-1 text-sm text-gray-600">
                        Change the current service case status with an optional note.
                      </p>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <form onSubmit={handleUpdateStatus} className="space-y-4">
                    <div>
                      <label htmlFor="service-case-status-code" className="block text-sm font-medium text-gray-700">New status</label>
                      <select
                        id="service-case-status-code"
                        value={statusCode}
                        onChange={(event) => setStatusCode(event.target.value)}
                        className="mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                      >
                        <option value="">Choose a status</option>
                        {statusOptions.map((option) => (
                          <option key={option.value} value={option.value}>
                            {option.label}
                          </option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label htmlFor="service-case-status-note" className="block text-sm font-medium text-gray-700">Note</label>
                      <textarea
                        id="service-case-status-note"
                        value={statusNote}
                        onChange={(event) => setStatusNote(event.target.value)}
                        className="mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                        rows={3}
                        placeholder="Optional status note"
                      />
                    </div>
                    <div className="flex flex-wrap gap-3">
                      <Button type="submit" isLoading={actionLoading}>
                        Update Status
                      </Button>
                    </div>
                  </form>
                </CardContent>
              </Card>
            ) : null}

            {canSendDispatcherMessage ? (
              <Card className="shadow-md">
                <CardHeader>
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#002D62] text-white">
                      <MessageSquare className="h-5 w-5" aria-hidden />
                    </div>
                    <div>
                      <h2 className="text-lg font-semibold text-[#002D62]">Send Dispatcher Message</h2>
                      <p className="mt-1 text-sm text-gray-600">
                        Reply to the reporter and update the case conversation.
                      </p>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <form onSubmit={handleSendMessage} className="space-y-4">
                    <div>
                      <label htmlFor="dispatcher-reply-title" className="block text-sm font-medium text-gray-700">Subject optional</label>
                      <input
                        id="dispatcher-reply-title"
                        value={messageTitle}
                        onChange={(event) => setMessageTitle(event.target.value)}
                        className="mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                        placeholder="Brief subject, optional"
                      />
                    </div>
                    <div>
                      <label htmlFor="dispatcher-reply-description" className="block text-sm font-medium text-gray-700">Description</label>
                      <textarea
                        id="dispatcher-reply-description"
                        value={messageDescription}
                        onChange={(event) => setMessageDescription(event.target.value)}
                        className="mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                        rows={4}
                        placeholder="Optional dispatcher notes"
                      />
                    </div>
                    <div className="flex flex-wrap gap-3">
                      <Button type="submit" isLoading={actionLoading}>
                        Send Message
                      </Button>
                    </div>
                  </form>
                </CardContent>
              </Card>
            ) : !isTerminal ? (
              <Card className="shadow-md">
                <CardHeader>
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-slate-100 text-slate-700">
                      <MessageSquare className="h-5 w-5" aria-hidden />
                    </div>
                    <div>
                      <h2 className="text-lg font-semibold text-[#002D62]">Send Dispatcher Message</h2>
                      <p className="mt-1 text-sm text-gray-600">
                        Messaging is available only when the service case is under review.
                      </p>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <MessageBanner tone="info">
                    Move this case to Under Review before sending a dispatcher message.
                  </MessageBanner>
                </CardContent>
              </Card>
            ) : null}

            {!isTerminal ? (
              <Card className="shadow-md">
                <CardHeader>
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#002D62] text-white">
                      <ShieldCheck className="h-5 w-5" aria-hidden />
                    </div>
                    <div>
                      <h2 className="text-lg font-semibold text-[#002D62]">Assign Case</h2>
                      <p className="mt-1 text-sm text-gray-600">
                        Assign this service case to an operations user.
                      </p>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <form onSubmit={handleAssign} className="space-y-4">
                    <div>
                      <label htmlFor="service-case-assignee-uuid" className="block text-sm font-medium text-gray-700">Assignee Public UUID</label>
                      <input
                        id="service-case-assignee-uuid"
                        value={assignTo}
                        onChange={(event) => setAssignTo(event.target.value)}
                        className="mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                        placeholder="User public UUID"
                        required
                      />
                    </div>
                    <div>
                      <label htmlFor="service-case-assignment-note" className="block text-sm font-medium text-gray-700">Note</label>
                      <textarea
                        id="service-case-assignment-note"
                        value={assignNote}
                        onChange={(event) => setAssignNote(event.target.value)}
                        className="mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                        rows={3}
                        placeholder="Optional assignment note"
                      />
                    </div>
                    <div className="flex flex-wrap gap-3">
                      <Button type="submit" isLoading={actionLoading}>
                        Assign Case
                      </Button>
                    </div>
                  </form>
                </CardContent>
              </Card>
            ) : null}

            {!isTerminal ? (
              <Card className="shadow-md">
                <CardHeader>
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#002D62] text-white">
                      <ShieldCheck className="h-5 w-5" aria-hidden />
                    </div>
                    <div>
                      <h2 className="text-lg font-semibold text-[#002D62]">Resolve Case</h2>
                      <p className="mt-1 text-sm text-gray-600">
                        Close the case with a final resolution narrative.
                      </p>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <form onSubmit={handleResolve} className="space-y-4">
                    <div>
                      <label htmlFor="service-case-resolution-type" className="block text-sm font-medium text-gray-700">Resolution Type</label>
                      <select
                        id="service-case-resolution-type"
                        value={resolutionType}
                        onChange={(event) => setResolutionType(event.target.value)}
                        className="mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                      >
                        <option value="advice_given">Advice Given</option>
                        <option value="referred_to_facility">Referred to Facility</option>
                        <option value="escalated">Escalated</option>
                        <option value="no_action_needed">No Action Needed</option>
                        <option value="duplicate">Duplicate</option>
                      </select>
                    </div>
                    <div>
                      <label htmlFor="service-case-resolution-text" className="block text-sm font-medium text-gray-700">Resolution Narrative</label>
                      <textarea
                        id="service-case-resolution-text"
                        value={resolutionText}
                        onChange={(event) => setResolutionText(event.target.value)}
                        className="mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                        rows={4}
                        required
                      />
                    </div>
                    <div>
                      <label htmlFor="service-case-recommended-facility-id" className="block text-sm font-medium text-gray-700">Recommended Facility ID</label>
                      <input
                        id="service-case-recommended-facility-id"
                        value={recommendedFacilityId}
                        onChange={(event) => setRecommendedFacilityId(event.target.value)}
                        className="mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                        placeholder="Optional facility id"
                      />
                    </div>
                    <div className="flex flex-wrap gap-3">
                      <Button type="submit" isLoading={actionLoading}>
                        Resolve Case
                      </Button>
                    </div>
                  </form>
                </CardContent>
              </Card>
            ) : null}

          </div>
        ) : null}
      </div>
    </DashboardLayout>
  );
}
