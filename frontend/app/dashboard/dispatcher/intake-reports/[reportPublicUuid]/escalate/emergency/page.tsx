"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ConfirmModal } from "@/components/ui/ConfirmModal";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { MessageBanner, PageLoading } from "@/components/ui/StatusState";
import { apiPost, ensureAuthSession } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";

const labelClassName = "block text-sm font-medium text-gray-700";
const fieldClassName =
  "mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900 placeholder-gray-400 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35";
const optionalLabelClassName = "text-xs font-normal text-gray-500";

type EscalateResponse = {
  message?: string;
  incident?: {
    public_uuid?: string;
    incident_code?: string;
  };
};

export default function EscalateIntakeServiceCasePage() {
  const router = useRouter();
  const params = useParams();
  const reportPublicUuid = params.reportPublicUuid as string;

  const [isLoadingSession, setIsLoadingSession] = useState(true);
  const [severityCode, setSeverityCode] = useState("medium");
  const [incidentTitle, setIncidentTitle] = useState("");
  const [incidentDescription, setIncidentDescription] = useState("");
  const [escalationReason, setEscalationReason] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [successMessage, setSuccessMessage] = useState("");
  const [incidentPublicUuid, setIncidentPublicUuid] = useState("");
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

  async function escalateServiceCase() {
    if (!escalationReason.trim()) {
      setError("Escalation reason is required.");
      setConfirmOpen(false);
      return;
    }

    setLoading(true);
    setError("");
    setSuccessMessage("");
    setIncidentPublicUuid("");

    try {
      const data = await apiPost<EscalateResponse>(
        `/intake/reports/${reportPublicUuid}/escalate`,
        {
          severityCode,
          incidentTitle: incidentTitle.trim() || undefined,
          incidentDescription: incidentDescription.trim() || undefined,
          escalationReason: escalationReason.trim(),
        },
      );

      setSuccessMessage(data.message || "Service case escalated to emergency incident.");
      const nextIncidentPublicUuid = data.incident?.public_uuid ?? "";
      setIncidentPublicUuid(nextIncidentPublicUuid);
      if (nextIncidentPublicUuid) {
        router.push(`/dashboard/dispatcher/incidents/${nextIncidentPublicUuid}`);
      }
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Could not escalate this service case.",
      );
    } finally {
      setLoading(false);
      setConfirmOpen(false);
    }
  }

  if (isLoadingSession) {
    return <PageLoading label="Loading service case escalation" />;
  }

  return (
    <DashboardLayout
      title="Escalate Service Case"
      subtitle={`Create an emergency incident from ${reportPublicUuid}`}
      onLogout={handleLogout}
    >
      <div className="mx-auto max-w-3xl space-y-6">
        <ConfirmModal
          open={confirmOpen}
          title="Escalate service case?"
          message="This will create an emergency incident from the service case linked to this intake report."
          confirmLabel="Escalate"
          isLoading={loading}
          onConfirm={() => void escalateServiceCase()}
          onCancel={() => setConfirmOpen(false)}
        />

        <Card>
          <CardHeader>
            <h1 className="text-2xl font-bold text-gray-900">
              Escalate to Emergency
            </h1>
            <p className="text-sm text-gray-500">
              Use this path for reports already linked to a service case.
            </p>
          </CardHeader>

          <CardContent>
            {error && <ErrorAlert message={error} />}
            {successMessage && (
              <MessageBanner tone="success" className="mb-4">
                {successMessage}
              </MessageBanner>
            )}

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
                  onChange={(event) => setSeverityCode(event.target.value)}
                  className={fieldClassName}
                  disabled={Boolean(successMessage)}
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>

              <div>
                <label className={labelClassName}>
                  Escalation Reason
                </label>
                <textarea
                  value={escalationReason}
                  onChange={(event) => setEscalationReason(event.target.value)}
                  className={fieldClassName}
                  rows={4}
                  placeholder="Why does this service case need emergency response?"
                  required
                  disabled={Boolean(successMessage)}
                />
              </div>

              <div>
                <label className={labelClassName}>
                  Incident Title
                  <span className={optionalLabelClassName}> (optional)</span>
                </label>
                <input
                  value={incidentTitle}
                  onChange={(event) => setIncidentTitle(event.target.value)}
                  className={fieldClassName}
                  placeholder="Emergency response needed"
                  disabled={Boolean(successMessage)}
                />
              </div>

              <div>
                <label className={labelClassName}>
                  Incident Description
                  <span className={optionalLabelClassName}> (optional)</span>
                </label>
                <textarea
                  value={incidentDescription}
                  onChange={(event) => setIncidentDescription(event.target.value)}
                  className={fieldClassName}
                  rows={4}
                  placeholder="Add any context responders should know."
                  disabled={Boolean(successMessage)}
                />
              </div>

              <div className="flex flex-wrap gap-3">
                <Button type="submit" disabled={loading || Boolean(successMessage)}>
                  {loading ? "Escalating..." : "Escalate to Emergency"}
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
                {incidentPublicUuid ? (
                  <Button
                    type="button"
                    onClick={() =>
                      router.push(
                        `/dashboard/dispatcher/incidents/${incidentPublicUuid}`,
                      )
                    }
                  >
                    View Incident
                  </Button>
                ) : successMessage ? (
                  <Button
                    type="button"
                    onClick={() => router.push("/dashboard/dispatcher/incidents")}
                  >
                    View Emergency Incidents
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
