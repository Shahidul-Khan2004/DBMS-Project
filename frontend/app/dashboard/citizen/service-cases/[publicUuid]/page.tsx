"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { useParams, useRouter } from "next/navigation";
import { Clock3, FileText, MessageSquare, RefreshCw } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { EmptyState, MessageBanner, PageLoading } from "@/components/ui/StatusState";
import { ApiError, apiGet, apiPost } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { formatBangladeshTime } from "@/lib/datetime";
import {
  getServiceCaseStatusLabel,
  isServiceCaseEscalated,
} from "@/lib/service-case-status";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type {
  CitizenServiceCase,
  CitizenServiceCaseListResponse,
  CitizenServiceCaseMessagesResponse,
  ServiceCaseMessageResult,
  ServiceCaseMessageResponse,
} from "@/types/service-case";

function DetailRow({ label, value }: { label: string; value: string | null }) {
  return (
    <div>
      <p className="text-xs font-semibold uppercase text-[#42547A]">{label}</p>
      <p className="mt-1 break-words text-sm font-medium text-gray-900">
        {value || "-"}
      </p>
    </div>
  );
}

function formatLocation(location: CitizenServiceCase["location"] | null | undefined) {
  if (!location) return "-";
  return location.address_text || location.place_name || "Map location selected";
}

function messageAuthor(message: ServiceCaseMessageResult) {
  if (message.message_type === "admin_reply") {
    return message.sender?.full_name?.trim() || "Dispatcher/Admin";
  }
  if (message.message_type === "user_message") return "You";
  if (message.message_type === "system_note") return "System";
  return "System";
}

function fallbackSubject(messageType: string | null | undefined) {
  if (messageType === "admin_reply") return "Dispatcher/Admin message";
  if (messageType === "user_message") return "Your message";
  if (messageType === "system_note") return "System update";
  return "Message";
}

function normalizeMessage(message: ServiceCaseMessageResult) {
  if (message.subject !== undefined || message.body !== undefined) {
    const subject = message.subject?.trim();
    const body = message.body?.trim();

    return {
      subject: subject || fallbackSubject(message.message_type),
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

const terminalStatuses = new Set([
  "resolved",
  "closed",
  "cancelled",
  "escalated_to_emergency",
]);

const activeReplyStatuses = new Set([
  "submitted",
  "under_review",
  "awaiting_user_response",
]);

export default function CitizenServiceCaseDetailPage() {
  const router = useRouter();
  const params = useParams();
  const publicUuid = params.publicUuid as string;
  const isChecking = useAuthGuard(["citizen"]);
  const [serviceCase, setServiceCase] = useState<CitizenServiceCase | null>(null);
  const [messages, setMessages] = useState<ServiceCaseMessageResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [messagesLoading, setMessagesLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [messagesError, setMessagesError] = useState<string | null>(null);
  const [messageTitle, setMessageTitle] = useState("");
  const [messageDescription, setMessageDescription] = useState("");
  const [sending, setSending] = useState(false);
  const [successMessage, setSuccessMessage] = useState("");
  const [messageError, setMessageError] = useState<string | null>(null);
  const replySectionRef = useRef<HTMLDivElement | null>(null);
  const subjectInputRef = useRef<HTMLInputElement | null>(null);

  const statusCode = serviceCase?.status_code ?? "";
  const isTerminal = useMemo(() => terminalStatuses.has(statusCode), [statusCode]);
  const isEscalated = isServiceCaseEscalated(statusCode);
  const canReply = useMemo(
    () => activeReplyStatuses.has(statusCode) && !isTerminal,
    [isTerminal, statusCode],
  );
  const needsReply = statusCode === "awaiting_user_response";

  const loadMessages = useCallback(async () => {
    setMessagesLoading(true);
    setMessagesError(null);

    try {
      const data = await apiGet<CitizenServiceCaseMessagesResponse>(
        `/intake/service-cases/${publicUuid}/messages`,
      );
      setMessages(data.messages ?? []);
    } catch (err) {
      if (err instanceof ApiError && (err.status === 403 || err.status === 404)) {
        setMessagesError("Messages are not available for this service case.");
      } else {
        setMessagesError(
          err instanceof Error
            ? err.message
            : "Unexpected error while loading service case messages.",
        );
      }
      setMessages([]);
    } finally {
      setMessagesLoading(false);
    }
  }, [publicUuid]);

  const loadServiceCase = useCallback(async () => {
    setLoading(true);
    setError(null);
    setServiceCase(null);

    try {
      const data = await apiGet<CitizenServiceCaseListResponse>(
        "/intake/reports/my/service-cases",
      );
      const found = data.service_cases.find(
        (item) => item.public_uuid === publicUuid,
      );
      if (!found) {
        setError("Service case not found or unavailable to this account.");
      } else {
        setServiceCase(found);
      }
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

  useEffect(() => {
    if (isChecking) return;
    void loadServiceCase();
    void loadMessages();
  }, [isChecking, loadMessages, loadServiceCase]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  async function handleSubmitMessage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessageError(null);
    setSuccessMessage("");

    const nextTitle = messageTitle.trim() || "Reply";
    const nextDescription = messageDescription.trim();

    if (!nextDescription && !messageTitle.trim()) {
      setMessageError("Write a message before sending.");
      return;
    }

    setSending(true);
    try {
      const data = await apiPost<ServiceCaseMessageResponse>(
        `/intake/service-cases/${publicUuid}/messages`,
        {
          title: nextTitle,
          description: nextDescription || undefined,
        },
      );

      setSuccessMessage(data.message || "Reply sent successfully.");
      setMessageTitle("");
      setMessageDescription("");
      if (data.case_message) {
        setMessages((current) => [...current, data.case_message as ServiceCaseMessageResult]);
      }
      await loadMessages();
    } catch (err) {
      setMessageError(
        err instanceof Error
          ? err.message
          : "Could not send your reply. Please try again.",
      );
    } finally {
      setSending(false);
    }
  }

  function focusReplyForm() {
    replySectionRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    window.setTimeout(() => subjectInputRef.current?.focus(), 250);
  }

  if (isChecking) {
    return <PageLoading label="Loading service case details" />;
  }

  return (
    <DashboardLayout
      title="Service Case Details"
      subtitle={`Case ${serviceCase?.case_code ?? publicUuid}`}
      onLogout={handleLogout}
    >
      <div className="space-y-6">
        <div className="flex flex-col gap-3 sm:flex-row sm:justify-start">
          <Button
            type="button"
            variant="secondary"
            onClick={() => router.push("/dashboard/citizen/service-cases")}
          >
            Back to Service Cases
          </Button>
        </div>

        {error && <ErrorAlert message={error} />}
        {needsReply && serviceCase ? (
          <MessageBanner tone="info">
            Dispatcher is awaiting your reply.
          </MessageBanner>
        ) : null}
        {isEscalated && serviceCase ? (
          <MessageBanner tone="info">
            This service case has been escalated to an emergency incident.
          </MessageBanner>
        ) : null}

        <Card className="!rounded-2xl !bg-white shadow-sm shadow-[#002D62]/5">
          <CardHeader>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#002D62] text-white">
                <Clock3 className="h-5 w-5" aria-hidden />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-[#002D62]">
                  Service Case Snapshot
                </h2>
                <p className="mt-1 text-sm text-gray-600">
                  Review details and send a message to the operations team.
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
                description="This case may no longer be available or may not belong to your account."
              />
            ) : (
              <div className="space-y-6">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div>
                    <p className="text-xs font-bold uppercase tracking-wide text-[#006747]">
                      Case Code
                    </p>
                    <p className="mt-0.5 text-sm font-semibold text-[#002D62]">
                      {serviceCase.case_code}
                    </p>
                    <h3 className="mt-1 text-xl font-semibold text-gray-900">
                      {serviceCase.title}
                    </h3>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {needsReply ? (
                      <Badge tone="awaiting_user_response">Needs your reply</Badge>
                    ) : null}
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

                <dl className="grid gap-4 sm:grid-cols-2">
                  <DetailRow label="Status" value={getServiceCaseStatusLabel(serviceCase.status_code)} />
                  <DetailRow label="Priority" value={formatBadgeLabel(serviceCase.priority_level)} />
                  <DetailRow label="Category" value={formatBadgeLabel(serviceCase.category_code)} />
                  <DetailRow label="Intake Report" value={serviceCase.intake_report_code} />
                  <DetailRow label="Last Updated" value={formatBangladeshTime(serviceCase.last_updated)} />
                  <DetailRow label="Created At" value={formatBangladeshTime(serviceCase.created_at)} />
                  <DetailRow label="Updated At" value={serviceCase.updated_at ? formatBangladeshTime(serviceCase.updated_at) : null} />
                </dl>

                <div className="rounded-2xl border border-[#002D62]/10 bg-[#EFF6FF] p-4">
                  <p className="text-sm font-semibold text-[#002D62]">Location</p>
                  <p className="mt-2 text-sm text-gray-700">
                    {formatLocation(serviceCase.location)}
                  </p>
                  <p className="mt-1 text-sm text-gray-700">
                    {serviceCase.location_text || ""}
                  </p>
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        {!loading && serviceCase ? (
          <Card className="!rounded-2xl !bg-white shadow-sm shadow-[#002D62]/5">
            <CardHeader>
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#002D62] text-white">
                  <MessageSquare className="h-5 w-5" aria-hidden />
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-[#002D62]">
                    Conversation
                  </h2>
                  <p className="mt-1 text-sm text-gray-600">
                    Messages between you and the operations team.
                  </p>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="mb-5 flex flex-wrap gap-3">
                <Button type="button" variant="secondary" onClick={loadMessages}>
                  <RefreshCw className="h-4 w-4" aria-hidden />
                  Refresh
                </Button>
                {needsReply && canReply ? (
                  <Button type="button" onClick={focusReplyForm}>
                    Reply now
                  </Button>
                ) : null}
              </div>

              {messagesLoading ? (
                <LoadingSkeleton lines={4} />
              ) : messagesError ? (
                <ErrorAlert message={messagesError} />
              ) : messages.length === 0 ? (
                <EmptyState
                  title="No messages yet"
                  description="Case messages from you and the operations team will appear here."
                  icon={<MessageSquare className="h-6 w-6" aria-hidden />}
                />
              ) : (
                <ul className="space-y-4">
                  {messages.map((message) => {
                    const parsed = normalizeMessage(message);
                    const fromCitizen = message.message_type === "user_message";

                    return (
                      <li
                        key={message.id}
                        className={`rounded-2xl border p-4 ${
                          fromCitizen
                            ? "border-[#006747]/20 bg-[#F0FDF4]"
                            : "border-[#002D62]/10 bg-white"
                        }`}
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div>
                            <p className="text-xs font-bold uppercase tracking-wide text-[#006747]">
                              {messageAuthor(message)}
                            </p>
                            <p className="mt-1 text-sm font-semibold text-gray-900">
                              {parsed.subject}
                            </p>
                          </div>
                          <span className="text-xs text-gray-500">
                            {formatBangladeshTime(message.created_at)}
                          </span>
                        </div>
                        {parsed.body ? (
                          <p className="mt-3 whitespace-pre-wrap text-sm leading-6 text-gray-700">
                            {parsed.body}
                          </p>
                        ) : (
                          <p className="mt-3 text-sm text-gray-500">
                            No additional message body.
                          </p>
                        )}
                      </li>
                    );
                  })}
                </ul>
              )}
            </CardContent>
          </Card>
        ) : null}

        {!loading && serviceCase ? (
          <div ref={replySectionRef}>
          <Card className="!rounded-2xl !bg-white shadow-sm shadow-[#002D62]/5">
            <CardHeader>
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#002D62] text-white">
                  <FileText className="h-5 w-5" aria-hidden />
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-[#002D62]">
                    Send a Message
                  </h2>
                  <p className="mt-1 text-sm text-gray-600">
                    Share an update or question with the operations team.
                  </p>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {isTerminal || !canReply ? (
                <MessageBanner tone="info">
                  {isEscalated
                    ? "This service case has been escalated to an emergency incident and cannot receive new replies."
                    : isTerminal
                    ? "This service case is final and cannot receive new replies."
                    : "Replies are not available for this service case status."}
                </MessageBanner>
              ) : (
                <>
                  {messageError && <ErrorAlert message={messageError} />}
                  {successMessage && (
                    <MessageBanner tone="success" className="mb-4">
                      {successMessage}
                    </MessageBanner>
                  )}

              <form onSubmit={handleSubmitMessage} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Subject optional</label>
                  <input
                    ref={subjectInputRef}
                    value={messageTitle}
                    onChange={(event) => setMessageTitle(event.target.value)}
                    className="mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                    placeholder="Brief subject, optional"
                    maxLength={255}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700">Description</label>
                  <textarea
                    value={messageDescription}
                    onChange={(event) => setMessageDescription(event.target.value)}
                    className="mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                    rows={5}
                    placeholder="Optional details or context"
                  />
                </div>
                <div className="flex flex-wrap gap-3">
                  <Button type="submit" isLoading={sending}>
                    Send Message
                  </Button>
                  <Button
                    type="button"
                    variant="secondary"
                    onClick={() => router.push("/dashboard/citizen/service-cases")}
                  >
                    Cancel
                  </Button>
                </div>
              </form>
                </>
              )}
            </CardContent>
          </Card>
          </div>
        ) : null}
      </div>
    </DashboardLayout>
  );
}
