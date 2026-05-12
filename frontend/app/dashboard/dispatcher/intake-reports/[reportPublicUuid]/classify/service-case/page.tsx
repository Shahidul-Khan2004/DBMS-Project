"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ConfirmModal } from "@/components/ui/ConfirmModal";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { MessageBanner, PageLoading } from "@/components/ui/StatusState";
import { ApiError, apiGet, apiPost, ensureAuthSession } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import type {
  OperationsIntakeReport,
  OperationsIntakeReportResponse,
} from "@/types/operations-intake";

const labelClassName = "block text-sm font-medium text-gray-700";
const fieldClassName =
  "mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900 placeholder-gray-400 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35";

type ServiceCaseResult = {
  public_uuid?: string;
  case_code?: string;
  title?: string;
  priority_level?: string;
};

type ClassifyServiceCaseResponse = {
  message?: string;
  service_case?: ServiceCaseResult;
};

function formatApiError(error: unknown, fallback: string) {
  if (error instanceof ApiError) {
    const hints: Record<string, string> = {
      SERVICE_CASE_REQUIRES_LOCATION:
        "Add or correct the reported location on this intake, then retry.",
      SERVICE_CASE_REQUIRES_REPORTER_USER:
        "This backend requires a reporter user before opening a service case.",
      INTAKE_ALREADY_LINKED:
        "Open the intake details to review the existing service case link.",
      INTAKE_NOT_CLASSIFIABLE:
        "Refresh the intake details and check its current status.",
    };
    const hint = error.code ? hints[error.code] : undefined;
    const codePrefix = error.code ? `${error.code}: ` : "";
    return `${codePrefix}${error.message}${hint ? ` ${hint}` : ""}`;
  }

  return error instanceof Error ? error.message : fallback;
}

export default function ClassifyIntakeAsServiceCasePage() {
  const router = useRouter();
  const params = useParams();
  const reportPublicUuid = params.reportPublicUuid as string;

  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [priorityLevel, setPriorityLevel] = useState("medium");
  const [isLoadingSession, setIsLoadingSession] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const [createdCase, setCreatedCase] = useState<ServiceCaseResult | null>(null);
  const [refreshedReport, setRefreshedReport] =
    useState<OperationsIntakeReport | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);

  const redirectToLogin = useCallback(() => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/auth/login");
  }, [router]);

  useEffect(() => {
    let cancelled = false;

    async function checkSession() {
      const token = await ensureAuthSession();
      const sessionUser = sessionStorage.getItem("loggedInUser");

      if (cancelled) return;

      if (!sessionUser || !token) {
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

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  async function classifyReport() {
    setLoading(true);
    setError("");
    setSuccessMessage("");
    setCreatedCase(null);
    setRefreshedReport(null);

    try {
      const token = await ensureAuthSession();

      if (!token) {
        redirectToLogin();
        return;
      }

      const data = await apiPost<ClassifyServiceCaseResponse>(
        `/intake/reports/${reportPublicUuid}/classify/service-case`,
        {
          title: title.trim() || undefined,
          description: description.trim() || undefined,
          priorityLevel,
        },
      );

      setSuccessMessage(data.message || "Intake classified as service case.");
      setCreatedCase(data.service_case ?? null);

      try {
        const detailData = await apiGet<OperationsIntakeReportResponse>(
          `/operations/intake-reports/${reportPublicUuid}`,
        );
        setRefreshedReport(detailData.intake_report);
      } catch (refreshError) {
        setError(
          `Classification succeeded, but latest intake details could not be loaded. ${formatApiError(
            refreshError,
            "Refresh failed.",
          )}`,
        );
      }
    } catch (err) {
      setError(formatApiError(err, "Classification failed."));
    } finally {
      setLoading(false);
      setConfirmOpen(false);
    }
  }

  if (isLoadingSession) {
    return <PageLoading label="Loading classification form" />;
  }

  return (
    <DashboardLayout
      title="Classify Intake"
      subtitle={`Create a service case from ${reportPublicUuid}`}
      onLogout={handleLogout}
    >
      <div className="mx-auto max-w-3xl space-y-6">
        <ConfirmModal
          open={confirmOpen}
          title="Classify as service case?"
          message="This will create a non-emergency service case from the intake report."
          confirmLabel="Classify"
          isLoading={loading}
          onConfirm={() => void classifyReport()}
          onCancel={() => setConfirmOpen(false)}
        />
        <Card>
          <CardHeader>
            <h1 className="text-2xl font-bold text-gray-900">
              Classify as Service Case
            </h1>
            <p className="text-sm text-gray-500">
              Create a non-emergency service case from this intake report.
            </p>
          </CardHeader>

          <CardContent>
            {error && <ErrorAlert message={error} />}
            {successMessage && (
              <MessageBanner tone="success" className="mb-4">
                {successMessage}
              </MessageBanner>
            )}

            {createdCase || refreshedReport ? (
              <div className="mb-5 rounded-2xl border border-[#002D62]/10 bg-[#EFF6FF] p-4">
                <h2 className="text-sm font-semibold text-[#002D62]">
                  Created Service Case
                </h2>
                <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
                  <div>
                    <dt className="font-medium text-gray-600">Case Code</dt>
                    <dd className="mt-1 text-gray-900">
                      {createdCase?.case_code ?? "-"}
                    </dd>
                  </div>
                  <div>
                    <dt className="font-medium text-gray-600">Priority</dt>
                    <dd className="mt-1 capitalize text-gray-900">
                      {createdCase?.priority_level ?? priorityLevel}
                    </dd>
                  </div>
                  <div className="sm:col-span-2">
                    <dt className="font-medium text-gray-600">Title</dt>
                    <dd className="mt-1 text-gray-900">
                      {createdCase?.title ?? "-"}
                    </dd>
                  </div>
                  <div>
                    <dt className="font-medium text-gray-600">
                      Latest Intake Status
                    </dt>
                    <dd className="mt-1 text-gray-900">
                      {refreshedReport?.intake_status ?? "-"}
                    </dd>
                  </div>
                  <div>
                    <dt className="font-medium text-gray-600">Public UUID</dt>
                    <dd className="mt-1 break-all text-gray-900">
                      {createdCase?.public_uuid ?? "-"}
                    </dd>
                  </div>
                </dl>
              </div>
            ) : null}

            <form
              onSubmit={(event) => {
                event.preventDefault();
                setConfirmOpen(true);
              }}
              className="space-y-4"
            >
              <div>
                <label className={labelClassName}>Title</label>
                <input
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  className={fieldClassName}
                  placeholder="Leave blank to use intake summary"
                />
              </div>

              <div>
                <label className={labelClassName}>Description</label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className={fieldClassName}
                  rows={4}
                  placeholder="Optional service case notes"
                />
              </div>

              <div>
                <label className={labelClassName}>Priority</label>
                <select
                  value={priorityLevel}
                  onChange={(e) => setPriorityLevel(e.target.value)}
                  className={fieldClassName}
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="urgent">Urgent</option>
                </select>
              </div>

              <div className="flex flex-wrap gap-3">
                <Button type="submit" disabled={loading || Boolean(successMessage)}>
                  {loading ? "Classifying..." : "Classify as Service Case"}
                </Button>

                <Button
                  type="button"
                  variant="secondary"
                  onClick={() =>
                    router.push(
                      `/dashboard/dispatcher/intake-reports/${reportPublicUuid}`,
                    )
                  }
                >
                  {successMessage ? "Back to Intake" : "Cancel"}
                </Button>

                {successMessage ? (
                  <Button
                    type="button"
                    variant="secondary"
                    onClick={() => router.push("/dashboard/dispatcher/intake-reports")}
                  >
                    Back to Queue
                  </Button>
                ) : null}
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
