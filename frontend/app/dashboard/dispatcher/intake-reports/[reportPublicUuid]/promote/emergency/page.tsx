"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { clearAuthSession, getValidAccessToken } from "@/lib/auth-store";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

const labelClassName = "block text-sm font-medium text-gray-700";
const fieldClassName =
  "mt-1 w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-gray-900 placeholder-gray-400";

export default function PromoteIntakeToEmergencyPage() {
  const router = useRouter();
  const params = useParams();
  const reportPublicUuid = params.reportPublicUuid as string;

  const [severityCode, setSeverityCode] = useState("high");
  const [incidentTitle, setIncidentTitle] = useState("");
  const [incidentDescription, setIncidentDescription] = useState("");
  const [reportedAt, setReportedAt] = useState("");
  const [isLoadingSession, setIsLoadingSession] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const redirectToLogin = useCallback(() => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/auth/login");
  }, [router]);

  useEffect(() => {
    const sessionUser = sessionStorage.getItem("loggedInUser");
    const token = getValidAccessToken();

    if (!sessionUser || !token) {
      redirectToLogin();
      return;
    }

    setIsLoadingSession(false);
  }, [redirectToLogin]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");

    try {
      const token = getValidAccessToken();

      if (!token) {
        redirectToLogin();
        return;
      }

      const res = await fetch(
        `${API_BASE}/operations/intake-reports/${reportPublicUuid}/promote/emergency`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            severityCode,
            incidentTitle: incidentTitle || undefined,
            incidentDescription: incidentDescription || undefined,
            reportedAt: reportedAt
              ? new Date(reportedAt).toISOString()
              : new Date().toISOString(),
          }),
        },
      );

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(
          data?.error?.message ||
            data?.message ||
            data?.code ||
            "Promotion failed",
        );
      }

      router.push(`/dashboard/dispatcher/incidents/${data.incident.public_uuid}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong");
    } finally {
      setLoading(false);
    }
  }

  if (isLoadingSession) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        Loading...
      </div>
    );
  }

  return (
    <DashboardLayout
      title="Promote Intake to Emergency"
      subtitle={`Create an emergency incident from ${reportPublicUuid}`}
      onLogout={handleLogout}
    >
      <div className="mx-auto max-w-3xl space-y-6">
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
            {error && (
              <div className="mb-4 rounded-md bg-red-50 p-3 text-sm text-red-700">
                {error}
              </div>
            )}

            <form onSubmit={handleSubmit} className="space-y-4">
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
                  Reported At
                </label>
                <input
                  type="datetime-local"
                  value={reportedAt}
                  onChange={(e) => setReportedAt(e.target.value)}
                  className={fieldClassName}
                />
              </div>

              <div className="flex gap-3">
                <Button type="submit" disabled={loading}>
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
                  Cancel
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
