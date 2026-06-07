"use client";

import dynamic from "next/dynamic";
import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { useParams, useRouter } from "next/navigation";
import {
  FileText,
  Headphones,
  MapPin,
  RefreshCw,
  Send,
} from "lucide-react";
import { getValidReportedCoordinates } from "@/components/dispatcher/triage/reportedLocationCoords";
import {
  CitizenBackButton,
  CitizenPageContent,
} from "@/components/citizen/CitizenPortal";
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

const ReportedLocationMapPreview = dynamic(
  () =>
    import("@/components/dispatcher/triage/ReportedLocationMapPreview").then(
      (mod) => ({ default: mod.ReportedLocationMapPreview }),
    ),
  {
    ssr: false,
    loading: () => (
      <div className="h-[220px] w-full animate-pulse rounded-lg bg-slate-100" />
    ),
  },
);

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
    return message.sender?.full_name?.trim() || "Operations team";
  }
  if (message.message_type === "user_message") return "You";
  if (message.message_type === "system_note") return "System";
  return "System";
}

function fallbackSubject(messageType: string | null | undefined) {
  if (messageType === "admin_reply") return "Operations team message";
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
  const [sendMessageOpen, setSendMessageOpen] = useState(false);
  const [messageError, setMessageError] = useState<string | null>(null);
  const [desktopMapOpen, setDesktopMapOpen] = useState(false);

  const statusCode = serviceCase?.status_code ?? "";
  const isTerminal = useMemo(() => terminalStatuses.has(statusCode), [statusCode]);
  const isEscalated = isServiceCaseEscalated(statusCode);
  const canReply = useMemo(
    () => activeReplyStatuses.has(statusCode) && !isTerminal,
    [isTerminal, statusCode],
  );
  const needsReply = statusCode === "awaiting_user_response";
  const locationCoordinates = useMemo(() => {
    if (!serviceCase?.location) return null;
    return getValidReportedCoordinates(
      serviceCase.location.latitude,
      serviceCase.location.longitude,
    );
  }, [serviceCase?.location]);
  const hasLocation = Boolean(
    serviceCase && (serviceCase.location || serviceCase.location_text),
  );

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

  useEffect(() => {
    setDesktopMapOpen(false);
  }, [publicUuid]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  function closeSendMessageModal() {
    if (sending) return;
    setSendMessageOpen(false);
    setMessageError(null);
  }

  async function handleSubmitMessage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessageError(null);

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

      setMessageTitle("");
      setMessageDescription("");
      setSendMessageOpen(false);
      setMessageError(null);
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
      subtitle={serviceCase?.title ?? "Track your service case and messages."}
      onLogout={handleLogout}
      contentClassName="flex min-h-0 flex-col lg:h-[calc(100vh-12rem)] lg:overflow-hidden"
    >
      <CitizenPageContent className="flex min-h-0 flex-1 flex-col !space-y-3 !py-0 sm:!space-y-3 lg:min-h-0 lg:overflow-hidden">
        <CitizenBackButton
          href="/dashboard/citizen/service-cases"
          label="Back to Service Cases"
        />

        <div className="grid min-h-0 flex-1 gap-4 xl:grid-cols-2 xl:items-stretch xl:overflow-hidden">
          <div className="flex min-h-0 min-w-0 flex-col gap-4 xl:h-full xl:overflow-hidden">
            <Card
              className={`overflow-hidden !rounded-2xl !border-slate-200/80 !bg-white shadow-sm ${
                hasLocation
                  ? "shrink-0"
                  : "flex min-h-[240px] flex-1 flex-col xl:min-h-0"
              }`}
            >
              <CardContent
                className={`!p-4 ${
                  hasLocation
                    ? ""
                    : "min-h-0 flex-1 overflow-y-auto overscroll-y-contain"
                }`}
              >
                {error ? <ErrorAlert message={error} /> : null}
                {needsReply && serviceCase ? (
                  <MessageBanner tone="info" className="mb-3">
                    The operations team is awaiting your reply.
                  </MessageBanner>
                ) : null}
                {isEscalated && serviceCase ? (
                  <MessageBanner tone="info" className="mb-3">
                    This service case has been escalated to an emergency response.
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
                    <div className="flex flex-col gap-2 border-b border-slate-200/80 pb-3 sm:flex-row sm:items-start sm:justify-between">
                      <div className="flex min-w-0 items-center gap-2.5">
                        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-[#002D62] text-white">
                          <FileText className="h-4 w-4" aria-hidden />
                        </div>
                        <div className="min-w-0">
                          <h2 className="text-base font-bold text-[#002D62]">
                            Service Case Overview
                          </h2>
                          <p className="mt-0.5 break-words text-sm font-medium text-slate-900">
                            {serviceCase.title}
                          </p>
                        </div>
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

                    <dl className="mt-3 grid gap-x-4 gap-y-2.5 sm:grid-cols-2">
                      <DetailRow
                        label="Category"
                        value={formatBadgeLabel(serviceCase.category_code)}
                      />
                      <DetailRow
                        label="Created"
                        value={formatBangladeshTime(serviceCase.created_at)}
                      />
                      <DetailRow
                        label="Last Updated"
                        value={formatBangladeshTime(serviceCase.last_updated)}
                      />
                    </dl>

                    {serviceCase.description ? (
                      <div className="mt-3">
                        <DetailRow label="Description" value={serviceCase.description} />
                      </div>
                    ) : null}
                  </>
                )}
              </CardContent>
            </Card>

            {!loading && hasLocation ? (
              <Card className="flex min-h-[200px] flex-1 flex-col overflow-hidden !rounded-2xl !border-slate-200/80 !bg-white shadow-sm xl:min-h-0">
                <CardHeader className="!border-b !border-slate-200/80 !px-4 !py-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex min-w-0 items-center gap-2.5">
                      <MapPin className="h-4 w-4 shrink-0 text-[#002D62]" aria-hidden />
                      <h2 className="text-sm font-semibold text-[#002D62]">Location</h2>
                    </div>
                    {locationCoordinates ? (
                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        className="hidden shrink-0 xl:inline-flex"
                        onClick={() => setDesktopMapOpen((open) => !open)}
                        aria-expanded={desktopMapOpen}
                      >
                        {desktopMapOpen ? "Hide map" : "View map"}
                      </Button>
                    ) : null}
                  </div>
                </CardHeader>
                <CardContent className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain !p-4">
                  <p className="break-words text-sm text-gray-800">
                    {formatLocation(serviceCase!.location)}
                    {serviceCase!.location_text &&
                    serviceCase!.location_text !== formatLocation(serviceCase!.location)
                      ? `, ${serviceCase!.location_text}`
                      : ""}
                  </p>
                  {locationCoordinates ? (
                    <>
                      <div className="mt-3 xl:hidden">
                        <ReportedLocationMapPreview
                          previewKey={serviceCase!.public_uuid}
                          latitude={locationCoordinates.latitude}
                          longitude={locationCoordinates.longitude}
                          addressText={serviceCase!.location?.address_text ?? undefined}
                          placeName={serviceCase!.location?.place_name ?? undefined}
                          heightClassName="h-[180px]"
                        />
                      </div>
                      {desktopMapOpen ? (
                        <div className="mt-3 hidden xl:block">
                          <ReportedLocationMapPreview
                            previewKey={serviceCase!.public_uuid}
                            latitude={locationCoordinates.latitude}
                            longitude={locationCoordinates.longitude}
                            addressText={serviceCase!.location?.address_text ?? undefined}
                            placeName={serviceCase!.location?.place_name ?? undefined}
                            heightClassName="h-[180px]"
                          />
                        </div>
                      ) : null}
                    </>
                  ) : null}
                </CardContent>
              </Card>
            ) : null}
          </div>

          {!loading && serviceCase ? (
            <div className="flex min-h-0 min-w-0 flex-col xl:h-full">
              <div className="flex h-full min-h-[320px] flex-col overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-sm xl:min-h-0">
                <div className="shrink-0 border-b border-slate-200/80 px-4 py-3">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <h2 className="text-sm font-semibold text-slate-900">Conversation</h2>
                      <p className="mt-0.5 text-xs text-slate-600">
                        Messages between you and the operations team.
                      </p>
                    </div>
                    <div className="flex shrink-0 flex-wrap items-center justify-end gap-2">
                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        onClick={() => void loadMessages()}
                        disabled={messagesLoading}
                      >
                        <RefreshCw className="h-4 w-4" aria-hidden />
                        Refresh
                      </Button>
                      {canReply ? (
                        <Button
                          type="button"
                          size="sm"
                          onClick={() => {
                            setMessageError(null);
                            setSendMessageOpen(true);
                          }}
                        >
                          <Send className="h-4 w-4" aria-hidden />
                          Send Message
                        </Button>
                      ) : null}
                    </div>
                  </div>
                  {!canReply ? (
                    <MessageBanner tone="info" className="mt-2">
                      {isEscalated
                        ? "This service case has been escalated to an emergency response and cannot receive new replies."
                        : isTerminal
                          ? "This service case is final and cannot receive new replies."
                          : "Replies are not available for this service case status."}
                    </MessageBanner>
                  ) : null}
                </div>

                <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain px-4 py-3">
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
                    <ul className="space-y-3">
                      {messages.map((message) => {
                        const parsed = normalizeMessage(message);
                        const fromCitizen = message.message_type === "user_message";

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
                                fromCitizen ? "bg-[#EFF6FF]" : "bg-[#F6F9FE]"
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
                </div>
              </div>
            </div>
          ) : null}
        </div>
      </CitizenPageContent>

      {sendMessageOpen && canReply ? (
        <div
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 px-4"
          onClick={closeSendMessageModal}
          role="presentation"
        >
          <form
            onSubmit={handleSubmitMessage}
            onClick={(event) => event.stopPropagation()}
            className="flex max-h-[90vh] w-full max-w-lg flex-col overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-xl"
          >
            <div className="shrink-0 border-b border-slate-200/80 px-5 py-4">
              <h2 className="text-lg font-semibold text-[#002D62]">Send a Message</h2>
            </div>
            <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-5 py-4">
              {messageError ? <ErrorAlert message={messageError} /> : null}
              <div>
                <label
                  htmlFor="service-case-message-subject"
                  className="block text-sm font-semibold text-[#002D62]"
                >
                  Subject <span className="text-[#B91C1C]">*</span>
                </label>
                <input
                  id="service-case-message-subject"
                  value={messageTitle}
                  onChange={(event) => setMessageTitle(event.target.value)}
                  className="mt-2 h-11 w-full rounded-xl border border-[#002D62]/20 bg-white px-4 text-sm text-gray-900 placeholder:text-[#7890BD] focus:border-[#0B3FE8] focus:outline-none focus:ring-2 focus:ring-[#0B3FE8]/20"
                  placeholder="Brief subject"
                  maxLength={255}
                  required
                  disabled={sending}
                />
              </div>
              <div>
                <label
                  htmlFor="service-case-message-body"
                  className="block text-sm font-semibold text-[#002D62]"
                >
                  Message <span className="text-[#B91C1C]">*</span>
                </label>
                <textarea
                  id="service-case-message-body"
                  value={messageDescription}
                  onChange={(event) => setMessageDescription(event.target.value)}
                  className="mt-2 min-h-[140px] w-full resize-none rounded-xl border border-[#002D62]/20 bg-white px-4 py-3 text-sm text-gray-900 placeholder:text-[#7890BD] focus:border-[#0B3FE8] focus:outline-none focus:ring-2 focus:ring-[#0B3FE8]/20"
                  placeholder="Type your message here..."
                  required
                  disabled={sending}
                />
              </div>
            </div>
            <div className="flex shrink-0 justify-end gap-3 border-t border-slate-200/80 px-5 py-4">
              <Button
                type="button"
                variant="secondary"
                onClick={closeSendMessageModal}
                disabled={sending}
              >
                Cancel
              </Button>
              <Button type="submit" isLoading={sending} disabled={sending}>
                <Send className="h-4 w-4" aria-hidden />
                Send Message
              </Button>
            </div>
          </form>
        </div>
      ) : null}
    </DashboardLayout>
  );
}
