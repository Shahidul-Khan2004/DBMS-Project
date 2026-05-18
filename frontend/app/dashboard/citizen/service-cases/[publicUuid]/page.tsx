"use client";

import { useCallback, useEffect, useState, type FormEvent } from "react";
import { useParams, useRouter } from "next/navigation";
import { Clock3, FileText, MapPin } from "lucide-react";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { EmptyState, MessageBanner, PageLoading } from "@/components/ui/StatusState";
import { apiGet, apiPost } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { formatBangladeshTime } from "@/lib/datetime";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type {
  CitizenServiceCase,
  CitizenServiceCaseListResponse,
  ServiceCaseMessageResponse,
} from "@/types/service-case";

function DetailRow({ label, value }: { label: string; value: string | null }) {
  return (
    <div>
      <p className="text-sm font-medium text-gray-600">{label}</p>
      <p className="mt-1 break-all text-sm text-gray-900">{value || "-"}</p>
    </div>
  );
}

function formatLocation(location: CitizenServiceCase["location"] | null | undefined) {
  if (!location) return "-";
  return location.address_text || location.place_name || "Map location selected";
}

export default function CitizenServiceCaseDetailPage() {
  const router = useRouter();
  const params = useParams();
  const publicUuid = params.publicUuid as string;
  const isChecking = useAuthGuard(["citizen"]);
  const [serviceCase, setServiceCase] = useState<CitizenServiceCase | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [messageTitle, setMessageTitle] = useState("");
  const [messageDescription, setMessageDescription] = useState("");
  const [sending, setSending] = useState(false);
  const [successMessage, setSuccessMessage] = useState("");
  const [messageError, setMessageError] = useState<string | null>(null);

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
  }, [isChecking, loadServiceCase]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  async function handleSubmitMessage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessageError(null);
    setSuccessMessage("");

    if (!messageTitle.trim()) {
      setMessageError("Subject is required.");
      return;
    }

    setSending(true);
    try {
      const data = await apiPost<ServiceCaseMessageResponse>(
        `/intake/service-cases/${publicUuid}/messages`,
        {
          title: messageTitle.trim(),
          description: messageDescription.trim() || undefined,
        },
      );

      setSuccessMessage(data.message || "Reply sent successfully.");
      setMessageTitle("");
      setMessageDescription("");
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
    >
      <div className="space-y-6">
        <div className="flex flex-col gap-3 sm:flex-row sm:justify-end">
          <Button
            type="button"
            variant="secondary"
            onClick={() => router.push("/dashboard/citizen/service-cases")}
          >
            Back to Service Cases
          </Button>
        </div>

        {error && <ErrorAlert message={error} />}

        <Card className="shadow-md">
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
                    <p className="text-sm font-bold uppercase tracking-wide text-gray-600">
                      Case ID
                    </p>
                    <p className="mt-0.5 text-sm text-gray-600">
                      {serviceCase.case_code}
                    </p>
                    <h3 className="mt-1 text-xl font-semibold text-gray-900">
                      {serviceCase.title}
                    </h3>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    <Badge tone={serviceCase.status_code}>
                      {formatBadgeLabel(serviceCase.status_code)}
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
                  <DetailRow label="Status" value={formatBadgeLabel(serviceCase.status_code)} />
                  <DetailRow label="Priority" value={formatBadgeLabel(serviceCase.priority_level)} />
                  <DetailRow label="Category" value={formatBadgeLabel(serviceCase.category_code)} />
                  <DetailRow label="Intake Report" value={serviceCase.intake_report_code} />
                  <DetailRow label="Last Updated" value={formatBangladeshTime(serviceCase.last_updated)} />
                  <DetailRow label="Created At" value={formatBangladeshTime(serviceCase.created_at)} />
                  <DetailRow label="Updated At" value={serviceCase.updated_at ? formatBangladeshTime(serviceCase.updated_at) : null} />
                  <DetailRow label="Public UUID" value={serviceCase.public_uuid} />
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
          <Card className="shadow-md">
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
              {messageError && <ErrorAlert message={messageError} />}
              {successMessage && (
                <MessageBanner tone="success" className="mb-4">
                  {successMessage}
                </MessageBanner>
              )}

              <form onSubmit={handleSubmitMessage} className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700">Subject</label>
                  <input
                    value={messageTitle}
                    onChange={(event) => setMessageTitle(event.target.value)}
                    className="mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                    placeholder="Brief subject"
                    maxLength={255}
                    required
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
            </CardContent>
          </Card>
        ) : null}
      </div>
    </DashboardLayout>
  );
}
