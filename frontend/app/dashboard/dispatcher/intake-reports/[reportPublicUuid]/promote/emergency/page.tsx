"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ConfirmModal } from "@/components/ui/ConfirmModal";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { MessageBanner, PageLoading } from "@/components/ui/StatusState";
import { ApiError, apiGet, apiPost, ensureAuthSession } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import {
  formatBangladeshTime,
  getCurrentBangladeshDatetimeLocal,
  isValidBangladeshLocalDatetime,
  toBangladeshIsoDatetime,
} from "@/lib/datetime";
import type {
  OperationsIntakeReport,
  OperationsIntakeReportResponse,
} from "@/types/operations-intake";

const labelClassName = "block text-sm font-medium text-gray-700";
const fieldClassName =
  "mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900 placeholder-gray-400 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35";
const optionalLabelClassName = "text-xs font-normal text-gray-500";

type PromotedIncidentResult = {
  public_uuid?: string;
  incident_code?: string;
  title?: string;
  severity_code?: string;
  status_code?: string;
  reported_at?: string | null;
};

type PromoteEmergencyResponse = {
  message?: string;
  incident?: PromotedIncidentResult;
};

function formatApiError(error: unknown, fallback: string) {
  if (error instanceof ApiError) {
    const hints: Record<string, string> = {
      EMERGENCY_INCIDENT_REQUIRES_LOCATION:
        "Add or correct the reported location on this intake, then retry.",
      INTAKE_NOT_PROMOTABLE:
        "Refresh the intake details and check its current status.",
      INTAKE_ALREADY_LINKED:
        "Open the intake details to review the existing emergency link.",
    };
    const hint = error.code ? hints[error.code] : undefined;
    const codePrefix = error.code ? `${error.code}: ` : "";
    return `${codePrefix}${error.message}${hint ? ` ${hint}` : ""}`;
  }

  return error instanceof Error ? error.message : fallback;
}

export default function PromoteIntakeToEmergencyPage() {
  const router = useRouter();
  const params = useParams();
  const reportPublicUuid = params.reportPublicUuid as string;

  const [severityCode, setSeverityCode] = useState("high");
  const [incidentTitle, setIncidentTitle] = useState("");
  const [incidentDescription, setIncidentDescription] = useState("");
  const [callerPhoneNumber, setCallerPhoneNumber] = useState("");
  const [callStartedAt, setCallStartedAt] = useState(
    getCurrentBangladeshDatetimeLocal(),
  );
  const [reportedAt, setReportedAt] = useState(getCurrentBangladeshDatetimeLocal());
  const [isLoadingSession, setIsLoadingSession] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const [promotedIncident, setPromotedIncident] =
    useState<PromotedIncidentResult | null>(null);
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

  async function promoteIntake() {
    setLoading(true);
    setError("");
    setSuccessMessage("");
    setPromotedIncident(null);
    setRefreshedReport(null);

    try {
      const token = await ensureAuthSession();

      if (!token) {
        redirectToLogin();
        return;
      }

      const incidentTitleText = incidentTitle.trim();
      const incidentDescriptionText = incidentDescription.trim();
      const callerPhoneNumberText = callerPhoneNumber.trim();

      if (callStartedAt && !isValidBangladeshLocalDatetime(callStartedAt)) {
        setError("Call started time must be a valid Bangladesh date and time.");
        return;
      }

      if (reportedAt && !isValidBangladeshLocalDatetime(reportedAt)) {
        setError("Reported time must be a valid Bangladesh date and time.");
        return;
      }

      const data = await apiPost<PromoteEmergencyResponse>(
        `/operations/intake-reports/${reportPublicUuid}/promote/emergency`,
        {
          severityCode,
          incidentTitle: incidentTitleText || undefined,
          incidentDescription: incidentDescriptionText || undefined,
          callerPhoneNumber: callerPhoneNumberText || undefined,
          callStartedAt: toBangladeshIsoDatetime(callStartedAt),
          reportedAt: toBangladeshIsoDatetime(reportedAt),
        },
      );

      setSuccessMessage(data.message || "Intake promoted to emergency incident.");
      setPromotedIncident(data.incident ?? null);

      try {
        const detailData = await apiGet<OperationsIntakeReportResponse>(
          `/operations/intake-reports/${reportPublicUuid}`,
        );
        setRefreshedReport(detailData.intake_report);
      } catch (refreshError) {
        setError(
          `Promotion succeeded, but latest intake details could not be loaded. ${formatApiError(
            refreshError,
            "Refresh failed.",
          )}`,
        );
      }
    } catch (err) {
      setError(formatApiError(err, "Promotion failed."));
    } finally {
      setLoading(false);
      setConfirmOpen(false);
    }
  }

  if (isLoadingSession) {
    return <PageLoading label="Loading emergency promotion" />;
  }

  return (
    <DashboardLayout
      title="Promote Intake to Emergency"
      subtitle={`Create an emergency incident from ${reportPublicUuid}`}
      onLogout={handleLogout}
    >
      <div className="mx-auto max-w-3xl space-y-6">
        <ConfirmModal
          open={confirmOpen}
          title="Promote intake to emergency?"
          message="This will create an emergency incident from the intake report and move it onto the emergency path."
          confirmLabel="Promote"
          isLoading={loading}
          onConfirm={() => void promoteIntake()}
          onCancel={() => setConfirmOpen(false)}
        />
        <Card>
          <CardHeader>
            <h1 className="text-2xl font-bold text-gray-900">
              Promote Intake to Emergency
            </h1>
            <p className="text-sm text-gray-500">
              Create an emergency incident from this intake report.
            </p>
          </CardHeader>

          <CardContent>
            {error && <ErrorAlert message={error} />}
            {successMessage && (
              <MessageBanner tone="success" className="mb-4">
                {successMessage}
              </MessageBanner>
            )}

            {promotedIncident || refreshedReport ? (
              <div className="mb-5 rounded-2xl border border-[#002D62]/10 bg-[#EFF6FF] p-4">
                <h2 className="text-sm font-semibold text-[#002D62]">
                  Created Emergency Incident
                </h2>
                <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
                  <div>
                    <dt className="font-medium text-gray-600">Incident Code</dt>
                    <dd className="mt-1 text-gray-900">
                      {promotedIncident?.incident_code ?? "-"}
                    </dd>
                  </div>
                  <div>
                    <dt className="font-medium text-gray-600">Severity</dt>
                    <dd className="mt-1 capitalize text-gray-900">
                      {promotedIncident?.severity_code ?? severityCode}
                    </dd>
                  </div>
                  <div>
                    <dt className="font-medium text-gray-600">Status</dt>
                    <dd className="mt-1 text-gray-900">
                      {promotedIncident?.status_code ?? "-"}
                    </dd>
                  </div>
                  <div>
                    <dt className="font-medium text-gray-600">Reported At</dt>
                    <dd className="mt-1 text-gray-900">
                      {formatBangladeshTime(promotedIncident?.reported_at)}
                    </dd>
                  </div>
                  <div className="sm:col-span-2">
                    <dt className="font-medium text-gray-600">Title</dt>
                    <dd className="mt-1 text-gray-900">
                      {promotedIncident?.title ?? "-"}
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
                    <dt className="font-medium text-gray-600">Incident UUID</dt>
                    <dd className="mt-1 break-all text-gray-900">
                      {promotedIncident?.public_uuid ?? "-"}
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
                <label className={labelClassName}>Severity</label>
                <select
                  value={severityCode}
                  onChange={(e) => setSeverityCode(e.target.value)}
                  className={fieldClassName}
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>

              <div>
                <label className={labelClassName}>
                  Incident Title
                </label>
                <input
                  value={incidentTitle}
                  onChange={(e) => setIncidentTitle(e.target.value)}
                  className={fieldClassName}
                  placeholder="Unconscious patient near gate 2"
                />
              </div>

              <div>
                <label className={labelClassName}>
                  Incident Description
                  <span className={optionalLabelClassName}> (optional)</span>
                </label>
                <textarea
                  value={incidentDescription}
                  onChange={(e) => setIncidentDescription(e.target.value)}
                  className={fieldClassName}
                  rows={4}
                  placeholder="Security team found a person unresponsive..."
                />
              </div>

              <div>
                <label className={labelClassName}>
                  Caller Phone Number
                  <span className={optionalLabelClassName}> (optional)</span>
                </label>
                <input
                  value={callerPhoneNumber}
                  onChange={(e) => setCallerPhoneNumber(e.target.value)}
                  className={fieldClassName}
                  placeholder="01700000000"
                />
              </div>

              <div>
                <label className={labelClassName}>
                  Call Started At
                  <span className={optionalLabelClassName}> (optional)</span>
                </label>
                <input
                  type="datetime-local"
                  value={callStartedAt}
                  onChange={(e) => setCallStartedAt(e.target.value)}
                  className={fieldClassName}
                />
              </div>

              <div>
                <label className={labelClassName}>
                  Reported At
                </label>
                <input
                  type="datetime-local"
                  value={reportedAt}
                  onChange={(e) => setReportedAt(e.target.value)}
                  className={fieldClassName}
                />
              </div>

              <div className="flex flex-wrap gap-3">
                <Button type="submit" disabled={loading || Boolean(successMessage)}>
                  {loading ? "Promoting..." : "Promote to Emergency"}
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

                {promotedIncident?.public_uuid ? (
                  <Button
                    type="button"
                    onClick={() =>
                      router.push(
                        `/dashboard/dispatcher/incidents/${promotedIncident.public_uuid}`,
                      )
                    }
                  >
                    View Incident Details
                  </Button>
                ) : null}

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
