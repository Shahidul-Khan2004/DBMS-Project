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
import {
  formatBangladeshTime,
  isValidBangladeshLocalDatetime,
} from "@/lib/datetime";
import type {
  OperationsIntakeReport,
  OperationsIntakeReportResponse,
} from "@/types/operations-intake";

const labelClassName = "block text-sm font-medium text-gray-700";
const fieldClassName =
  "mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900 placeholder-gray-400 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35";

type EmergencyIncidentResult = {
  public_uuid?: string;
  incident_code?: string;
  title?: string;
  severity_code?: string;
  reported_at?: string | null;
};

type EmergencyCallResult = {
  id?: number | string;
  caller_phone_number?: string | null;
  call_started_at?: string | null;
  call_status?: string | null;
};

type ClassifyEmergencyResponse = {
  message?: string;
  emergency_incident?: EmergencyIncidentResult;
  incident?: EmergencyIncidentResult;
  emergency_call?: EmergencyCallResult;
};

function formatApiError(error: unknown, fallback: string) {
  if (error instanceof ApiError) {
    const hints: Record<string, string> = {
      EMERGENCY_INCIDENT_REQUIRES_LOCATION:
        "Add or correct the reported location on this intake, then retry.",
      INTAKE_ALREADY_LINKED:
        "Open the intake details to review the existing emergency link.",
      INTAKE_NOT_CLASSIFIABLE:
        "Refresh the intake details and check its current status.",
    };
    const hint = error.code ? hints[error.code] : undefined;
    const codePrefix = error.code ? `${error.code}: ` : "";
    return `${codePrefix}${error.message}${hint ? ` ${hint}` : ""}`;
  }

  return error instanceof Error ? error.message : fallback;
}

export default function ClassifyIntakeAsEmergencyPage() {
  const router = useRouter();
  const params = useParams();
  const reportPublicUuid = params.reportPublicUuid as string;

  const [severityCode, setSeverityCode] = useState("high");
  const [incidentTitle, setIncidentTitle] = useState("");
  const [incidentDescription, setIncidentDescription] = useState("");
  const [callerPhoneNumber, setCallerPhoneNumber] = useState("");
  const [callStartedAt, setCallStartedAt] = useState("");
  const [reportedAt, setReportedAt] = useState("");
  const [isLoadingSession, setIsLoadingSession] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const [createdIncident, setCreatedIncident] =
    useState<EmergencyIncidentResult | null>(null);
  const [createdCall, setCreatedCall] = useState<EmergencyCallResult | null>(
    null,
  );
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

  async function classifyEmergency() {
    setLoading(true);
    setError("");
    setSuccessMessage("");
    setCreatedIncident(null);
    setCreatedCall(null);
    setRefreshedReport(null);

    try {
      const token = await ensureAuthSession();
      if (!token) {
        redirectToLogin();
        return;
      }

      const callStartedAtPayload = callStartedAt || undefined;
      const reportedAtPayload = reportedAt || undefined;

      if (callStartedAt && !isValidBangladeshLocalDatetime(callStartedAt)) {
        setError("Call started time must be a valid Bangladesh date and time.");
        return;
      }

      if (reportedAt && !isValidBangladeshLocalDatetime(reportedAt)) {
        setError("Reported time must be a valid Bangladesh date and time.");
        return;
      }

      const data = await apiPost<ClassifyEmergencyResponse>(
        `/intake/reports/${reportPublicUuid}/classify/emergency`,
        {
          severityCode,
          incidentTitle: incidentTitle.trim() || undefined,
          incidentDescription: incidentDescription.trim() || undefined,
          callerPhoneNumber: callerPhoneNumber.trim() || undefined,
          callStartedAt: callStartedAtPayload,
          reportedAt: reportedAtPayload,
        },
      );

      setSuccessMessage(data.message || "Intake classified as emergency.");
      setCreatedIncident(data.emergency_incident ?? data.incident ?? null);
      setCreatedCall(data.emergency_call ?? null);

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
    return <PageLoading label="Loading emergency classification" />;
  }

  return (
    <DashboardLayout
      title="Classify as Emergency"
      subtitle={`Mark intake ${reportPublicUuid} as emergency`}
      onLogout={handleLogout}
    >
      <div className="mx-auto max-w-3xl space-y-6">
        <ConfirmModal
          open={confirmOpen}
          title="Classify as Emergency?"
          message="This will classify the intake report as an emergency and create the emergency path for review."
          confirmLabel="Classify"
          isLoading={loading}
          onConfirm={() => void classifyEmergency()}
          onCancel={() => setConfirmOpen(false)}
        />

        <Card>
          <CardHeader>
            <h1 className="text-2xl font-bold text-gray-900">
              Classify as Emergency
            </h1>
            <p className="text-sm text-gray-500">
              Send this intake report through the emergency classification workflow.
            </p>
          </CardHeader>

          <CardContent>
            {error && <ErrorAlert message={error} />}
            {successMessage && (
              <MessageBanner tone="success" className="mb-4">
                {successMessage}
              </MessageBanner>
            )}

            {createdIncident || createdCall || refreshedReport ? (
              <div className="mb-5 rounded-2xl border border-[#002D62]/10 bg-[#EFF6FF] p-4">
                <h2 className="text-sm font-semibold text-[#002D62]">
                  Created Emergency Path
                </h2>
                <dl className="mt-3 grid gap-3 text-sm sm:grid-cols-2">
                  <div>
                    <dt className="font-medium text-gray-600">Incident Code</dt>
                    <dd className="mt-1 text-gray-900">
                      {createdIncident?.incident_code ?? "-"}
                    </dd>
                  </div>
                  <div>
                    <dt className="font-medium text-gray-600">Severity</dt>
                    <dd className="mt-1 capitalize text-gray-900">
                      {createdIncident?.severity_code ?? severityCode}
                    </dd>
                  </div>
                  <div className="sm:col-span-2">
                    <dt className="font-medium text-gray-600">Incident Title</dt>
                    <dd className="mt-1 text-gray-900">
                      {createdIncident?.title ?? "-"}
                    </dd>
                  </div>
                  <div>
                    <dt className="font-medium text-gray-600">Call Status</dt>
                    <dd className="mt-1 text-gray-900">
                      {createdCall?.call_status ?? "-"}
                    </dd>
                  </div>
                  <div>
                    <dt className="font-medium text-gray-600">
                      Call Started At
                    </dt>
                    <dd className="mt-1 text-gray-900">
                      {formatBangladeshTime(createdCall?.call_started_at)}
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
                      {createdIncident?.public_uuid ?? "-"}
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
                <label htmlFor="severityCode" className={labelClassName}>
                  Severity
                </label>
                <select
                  id="severityCode"
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
                <label htmlFor="incidentTitle" className={labelClassName}>
                  Emergency Title
                </label>
                <input
                  id="incidentTitle"
                  value={incidentTitle}
                  onChange={(e) => setIncidentTitle(e.target.value)}
                  className={fieldClassName}
                  placeholder="Optional title for the emergency"
                />
              </div>

              <div>
                <label htmlFor="incidentDescription" className={labelClassName}>
                  Description
                </label>
                <textarea
                  id="incidentDescription"
                  value={incidentDescription}
                  onChange={(e) => setIncidentDescription(e.target.value)}
                  className={fieldClassName}
                  rows={4}
                  placeholder="Optional emergency description"
                />
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label htmlFor="callerPhoneNumber" className={labelClassName}>
                    Caller Phone Number
                  </label>
                  <input
                    id="callerPhoneNumber"
                    value={callerPhoneNumber}
                    onChange={(e) => setCallerPhoneNumber(e.target.value)}
                    className={fieldClassName}
                    placeholder="01700000000"
                  />
                </div>

                <div>
                  <label htmlFor="callStartedAt" className={labelClassName}>
                    Call Started At
                  </label>
                  <input
                    id="callStartedAt"
                    type="datetime-local"
                    value={callStartedAt}
                    onChange={(e) => setCallStartedAt(e.target.value)}
                    className={fieldClassName}
                  />
                </div>
              </div>

              <div>
                <label htmlFor="reportedAt" className={labelClassName}>
                  Reported At
                </label>
                <input
                  id="reportedAt"
                  type="datetime-local"
                  value={reportedAt}
                  onChange={(e) => setReportedAt(e.target.value)}
                  className={fieldClassName}
                />
              </div>

              <div className="flex flex-wrap gap-3">
                <Button type="submit" disabled={loading || Boolean(successMessage)}>
                  {loading ? "Classifying..." : "Classify as Emergency"}
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
                {createdIncident?.public_uuid ? (
                  <Button
                    type="button"
                    onClick={() =>
                      router.push(
                        `/dashboard/dispatcher/incidents/${createdIncident.public_uuid}`,
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
