"use client";

import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  ExternalLink,
  FileText,
  Headphones,
  MapPin,
  MessageSquare,
  RefreshCw,
  Send,
} from "lucide-react";
import { CitizenBackButton } from "@/components/citizen/CitizenPortal";
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

    const nextTitle = messageTitle.trim();
    const nextDescription = messageDescription.trim();

    if (!nextTitle) {
      setMessageError("Write a subject before sending.");
      return;
    }

    if (!nextDescription) {
      setMessageError("Write a message before sending.");
      return;
    }

    setSending(true);
    try {
      const data = await apiPost<ServiceCaseMessageResponse>(
        `/intake/service-cases/${publicUuid}/messages`,
        {
          title: nextTitle,
          description: nextDescription,
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

  if (isChecking) {
    return <PageLoading label="Loading service case details" />;
  }

  return (
    <DashboardLayout
      title="Service Case Details"
      subtitle={`Case ${serviceCase?.case_code ?? publicUuid}`}
      onLogout={handleLogout}
      contentClassName="h-[calc(100dvh-9rem)] min-h-0 overflow-hidden"
    >
      <div className="grid h-full min-h-0 items-start gap-3 overflow-y-auto overscroll-y-contain lg:grid-cols-[minmax(0,1.7fr)_minmax(320px,0.9fr)] lg:overflow-hidden">
        <div className="min-w-0 space-y-3 lg:min-h-0 lg:overflow-y-auto lg:overscroll-y-contain lg:pr-1">
          <Card className="shrink-0 !overflow-hidden !rounded-2xl !bg-white shadow-sm shadow-[#002D62]/5">
            <div className="border-b border-[#002D62]/10 px-4 py-3 sm:px-5">
              <CitizenBackButton
                href="/dashboard/citizen/service-cases"
                label="Back to Service Cases"
              />
            </div>
            <CardContent className="!p-4">
              {error ? <ErrorAlert message={error} /> : null}
              {needsReply && serviceCase ? (
                <MessageBanner tone="info" className="mb-3">
                  Dispatcher is awaiting your reply.
                </MessageBanner>
              ) : null}
              {isEscalated && serviceCase ? (
                <MessageBanner tone="info" className="mb-3">
                  This service case has been escalated to an emergency incident.
                </MessageBanner>
              ) : null}

              {loading ? (
                <LoadingSkeleton lines={6} />
              ) : !serviceCase ? (
                <EmptyState
                  title="Service case not found"
                  description="This case may no longer be available or may not belong to your account."
                />
              ) : (
                <>
                  <div className="flex flex-col gap-2 border-b border-[#002D62]/10 pb-3 sm:flex-row sm:items-center sm:justify-between">
                    <div className="flex min-w-0 items-center gap-3">
                      <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#002D62] text-white">
                        <FileText className="h-5 w-5" aria-hidden />
                      </div>
                      <h2 className="text-lg font-bold text-[#002D62]">
                        Service Case Snapshot
                      </h2>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {needsReply ? (
                        <Badge tone="awaiting_user_response">
                          Needs your reply
                        </Badge>
                      ) : null}
                      <Badge tone={serviceCase.status_code}>
                        {getServiceCaseStatusLabel(serviceCase.status_code)}
                      </Badge>
                      <Badge tone={serviceCase.priority_level}>
                        {formatBadgeLabel(serviceCase.priority_level)}
                      </Badge>
                    </div>
                  </div>

                  <dl className="mt-3 grid gap-x-4 gap-y-3 sm:grid-cols-2 xl:grid-cols-4">
                    <DetailRow label="Case Code" value={serviceCase.case_code} />
                    <DetailRow label="Title" value={serviceCase.title} />
                    <DetailRow
                      label="Category"
                      value={formatBadgeLabel(serviceCase.category_code)}
                    />
                    <DetailRow
                      label="Priority"
                      value={formatBadgeLabel(serviceCase.priority_level)}
                    />
                    <DetailRow
                      label="Intake Report"
                      value={serviceCase.intake_report_code}
                    />
                    <DetailRow
                      label="Status"
                      value={getServiceCaseStatusLabel(serviceCase.status_code)}
                    />
                    <DetailRow
                      label="Created At"
                      value={formatBangladeshTime(serviceCase.created_at)}
                    />
                    <DetailRow
                      label="Last Updated"
                      value={formatBangladeshTime(serviceCase.last_updated)}
                    />
                  </dl>

                  <div className="mt-3">
                    <DetailRow
                      label="Description"
                      value={serviceCase.description || "No description provided."}
                    />
                  </div>

                  <div className="mt-3">
                    <p className="text-xs font-semibold uppercase text-[#42547A]">
                      Location
                    </p>
                    <div className="mt-2 flex items-start gap-2 text-sm text-gray-800">
                      <MapPin
                        className="mt-0.5 h-4 w-4 shrink-0 text-[#0B3FE8]"
                        aria-hidden
                      />
                      <p className="break-words">
                        {formatLocation(serviceCase.location)}
                        {serviceCase.location_text &&
                        serviceCase.location_text !==
                          formatLocation(serviceCase.location)
                          ? `, ${serviceCase.location_text}`
                          : ""}
                      </p>
                    </div>
                    {serviceCase.location ? (
                      <a
                        href={`https://www.openstreetmap.org/?mlat=${serviceCase.location.latitude}&mlon=${serviceCase.location.longitude}#map=16/${serviceCase.location.latitude}/${serviceCase.location.longitude}`}
                        target="_blank"
                        rel="noreferrer"
                        className="mt-2 inline-flex items-center gap-1 text-sm font-semibold text-[#0B3FE8] hover:text-[#002D62]"
                      >
                        View on Map
                        <ExternalLink className="h-3.5 w-3.5" aria-hidden />
                      </a>
                    ) : null}
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          {!loading && serviceCase ? (
            <Card className="!overflow-hidden !rounded-2xl !bg-white shadow-sm shadow-[#002D62]/5">
              <CardHeader className="shrink-0 !px-4 !py-3 sm:!px-5">
                <div className="flex items-center justify-between gap-3">
                  <div className="flex min-w-0 items-center gap-3">
                    <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#002D62] text-white">
                      <MessageSquare className="h-5 w-5" aria-hidden />
                    </div>
                    <div className="min-w-0">
                      <h2 className="text-lg font-bold text-[#002D62]">
                        Conversation
                      </h2>
                      <p className="text-sm text-[#42547A]">
                        Messages between you and the operations team.
                      </p>
                    </div>
                  </div>
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    onClick={() => void loadMessages()}
                    disabled={messagesLoading}
                    className="shrink-0 rounded-xl"
                  >
                    <RefreshCw className="h-4 w-4" aria-hidden />
                    Refresh
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="!p-3 sm:!p-4">
                {messagesLoading ? (
                  <LoadingSkeleton lines={4} />
                ) : messagesError ? (
                  <ErrorAlert message={messagesError} />
                ) : messages.length === 0 ? (
                  <div className="rounded-xl border border-dashed border-[#002D62]/15 bg-[#F8FBFF] px-4 py-5 text-center">
                    <p className="text-sm font-semibold text-[#002D62]">
                      No messages yet
                    </p>
                    <p className="mt-1 text-sm text-[#42547A]">
                      Case messages from you and the operations team will appear here.
                    </p>
                  </div>
                ) : (
                  <ul className="max-h-[13rem] space-y-3 overflow-y-auto overscroll-y-contain pr-1">
                    {messages.map((message) => {
                      const parsed = normalizeMessage(message);
                      const fromCitizen =
                        message.message_type === "user_message";

                      return (
                        <li
                          key={message.id}
                          className={`flex gap-2 ${
                            fromCitizen ? "justify-end" : "justify-start"
                          }`}
                        >
                          {!fromCitizen ? (
                            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#0B3FE8] text-white">
                              <Headphones className="h-5 w-5" aria-hidden />
                            </div>
                          ) : null}
                          <div
                            className={`max-w-[min(78%,36rem)] rounded-2xl px-4 py-3 ${
                              fromCitizen
                                ? "bg-[#EFF6FF]"
                                : "bg-[#F6F9FE]"
                            }`}
                          >
                            <p className="text-sm font-bold text-[#002D62]">
                              {messageAuthor(message)}
                            </p>
                            {parsed.subject &&
                            parsed.subject !== fallbackSubject(message.message_type) ? (
                              <p className="mt-1 text-sm font-semibold text-gray-900">
                                {parsed.subject}
                              </p>
                            ) : null}
                            <p className="mt-1 whitespace-pre-wrap text-sm leading-6 text-gray-700">
                              {parsed.body || "No additional message body."}
                            </p>
                            <p className="mt-2 text-xs text-[#60739A]">
                              {formatBangladeshTime(message.created_at)}
                            </p>
                          </div>
                          {fromCitizen ? (
                            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-[#0B3FE8] text-sm font-bold text-white">
                              You
                            </div>
                          ) : null}
                        </li>
                      );
                    })}
                  </ul>
                )}
              </CardContent>
            </Card>
          ) : null}
        </div>

        {!loading && serviceCase ? (
          <Card className="min-w-0 self-start !overflow-hidden !rounded-2xl !bg-white shadow-sm shadow-[#002D62]/5">
            <CardHeader className="shrink-0 !px-4 !py-4">
              <div className="flex items-center gap-4">
                <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-full bg-[#002D62] text-white">
                  <Send className="h-5 w-5" aria-hidden />
                </div>
                <div>
                  <h2 className="text-xl font-bold text-[#002D62]">
                    Send a Message
                  </h2>
                  <p className="mt-1 text-sm text-[#42547A]">
                    Share an update or ask a question.
                  </p>
                </div>
              </div>
            </CardHeader>
            <CardContent className="!p-4">
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
                  {messageError ? (
                    <div className="mb-3">
                      <ErrorAlert message={messageError} />
                    </div>
                  ) : null}
                  {successMessage ? (
                    <MessageBanner tone="success" className="mb-3">
                      {successMessage}
                    </MessageBanner>
                  ) : null}
                  <form
                    onSubmit={handleSubmitMessage}
                    className="space-y-3"
                  >
                    <div className="shrink-0">
                      <label
                        htmlFor="service-case-message-subject"
                        className="block text-sm font-semibold text-[#002D62]"
                      >
                        Subject <span className="text-red-500">*</span>
                      </label>
                      <input
                        id="service-case-message-subject"
                        value={messageTitle}
                        onChange={(event) =>
                          setMessageTitle(event.target.value)
                        }
                        className="mt-2 h-12 w-full rounded-xl border border-[#002D62]/20 bg-white px-4 text-sm text-gray-900 placeholder:text-[#7890BD] focus:border-[#0B3FE8] focus:outline-none focus:ring-2 focus:ring-[#0B3FE8]/20"
                        placeholder="Brief subject"
                        maxLength={255}
                        required
                      />
                    </div>
                    <div>
                      <label
                        htmlFor="service-case-message-body"
                        className="block shrink-0 text-sm font-semibold text-[#002D62]"
                      >
                        Message <span className="text-red-600">*</span>
                      </label>
                      <textarea
                        id="service-case-message-body"
                        value={messageDescription}
                        onChange={(event) =>
                          setMessageDescription(event.target.value)
                        }
                        className="mt-2 h-44 w-full resize-none rounded-xl border border-[#002D62]/20 bg-white px-4 py-3 text-sm text-gray-900 placeholder:text-[#7890BD] focus:border-[#0B3FE8] focus:outline-none focus:ring-2 focus:ring-[#0B3FE8]/20"
                        placeholder="Type your message here..."
                        required
                      />
                      <p className="mt-2 shrink-0 text-xs text-[#60739A]">
                        {messageDescription.length} characters
                      </p>
                    </div>
                    <div className="flex shrink-0 flex-wrap gap-3">
                      <Button
                        type="submit"
                        isLoading={sending}
                        className="rounded-xl"
                      >
                        <Send className="h-4 w-4" aria-hidden />
                        Send Message
                      </Button>
                      <Button
                        type="button"
                        variant="secondary"
                        className="rounded-xl"
                        onClick={() => {
                          setMessageTitle("");
                          setMessageDescription("");
                          setMessageError(null);
                          setSuccessMessage("");
                        }}
                      >
                        Cancel
                      </Button>
                    </div>
                  </form>
                </>
              )}
            </CardContent>
          </Card>
        ) : null}
      </div>
    </DashboardLayout>
  );
}
