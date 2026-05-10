"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { clearAuthSession, getValidAccessToken } from "@/lib/auth-store";

interface Incident {
  public_uuid: string;
  incident_code: string;
  title: string;
  description: string | null;
  origin_type: string;
  status_code: string;
  category_code: string;
  severity_code: string;
  outcome_code: string | null;
  reported_at: string;
  resolved_at: string | null;
  closed_at: string | null;
  created_at: string;
  updated_at: string;
}

interface IncidentsResponse {
  incidents: Incident[];
  pagination: {
    limit: number;
    offset: number;
    total: number;
  };
}

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

export default function IncidentsPage() {
  const router = useRouter();
  const [isLoadingSession, setIsLoadingSession] = useState(true);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pagination, setPagination] = useState({ limit: 50, offset: 0, total: 0 });

  const redirectToLogin = useCallback(() => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/auth/login");
  }, [router]);

  const loadIncidents = useCallback(async (offset = 0) => {
    const accessToken = getValidAccessToken();
    if (!accessToken) {
      redirectToLogin();
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `${API_BASE}/operations/incidents?limit=50&offset=${offset}`,
        {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        }
      );

      const data = (await response.json().catch(() => ({}))) as
        | IncidentsResponse
        | { error?: { message?: string }; message?: string };

      if (!response.ok) {
        let errMsg = "Could not load incidents.";

        if ("error" in data && data.error?.message) {
          errMsg = data.error.message;
        } else if ("message" in data && typeof data.message === "string") {
          errMsg = data.message;
        }

        setError(errMsg);
        setIncidents([]);
        return;
      }

      const responseData = data as IncidentsResponse;
      setIncidents(responseData.incidents);
      setPagination(responseData.pagination);
    } catch {
      setError("Unexpected error while loading incidents.");
      setIncidents([]);
    } finally {
      setLoading(false);
    }
  }, [redirectToLogin]);

  useEffect(() => {
    const sessionUser = sessionStorage.getItem("loggedInUser");
    const accessToken = getValidAccessToken();

    if (!sessionUser || !accessToken) {
      redirectToLogin();
      return;
    }

    setIsLoadingSession(false);
  }, [redirectToLogin]);

  useEffect(() => {
    if (isLoadingSession) return;
    void loadIncidents();
  }, [isLoadingSession, loadIncidents]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  const formatDate = (iso: string) => {
    if (!iso) return "—";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString();
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "reported":
        return "bg-red-100 text-red-800";
      case "classified":
        return "bg-yellow-100 text-yellow-800";
      case "in_progress":
        return "bg-blue-100 text-blue-800";
      case "resolved":
        return "bg-green-100 text-green-800";
      case "closed":
        return "bg-gray-100 text-gray-800";
      case "cancelled":
        return "bg-gray-100 text-gray-800";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "critical":
        return "bg-red-100 text-red-800";
      case "high":
        return "bg-orange-100 text-orange-800";
      case "medium":
        return "bg-yellow-100 text-yellow-800";
      case "low":
        return "bg-green-100 text-green-800";
      default:
        return "bg-gray-100 text-gray-800";
    }
  };

  if (isLoadingSession) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        Loading...
      </div>
    );
  }

  return (
    <DashboardLayout
      title="Emergency Incidents"
      subtitle="Operations management for emergency incidents"
      onLogout={handleLogout}
    >
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">Emergency Incidents</h1>
            <p className="mt-1 text-sm text-gray-600">
              Total: {pagination.total} | Showing: {incidents.length}
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              type="button"
              variant="secondary"
              onClick={() => router.push("/dashboard/dispatcher")}
            >
              Back to Dashboard
            </Button>
            <Button
              type="button"
              onClick={() =>
                router.push("/dashboard/dispatcher/incidents/create-incident")
              }
            >
              Create Incident
            </Button>
            <Button
              type="button"
              variant="secondary"
              onClick={() => void loadIncidents()}
              disabled={loading}
            >
              {loading ? "Loading..." : "Refresh"}
            </Button>
          </div>
        </div>

        {error && (
          <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-sm text-red-800">
            <p>{error}</p>
          </div>
        )}

        <Card className="shadow-md">
          <CardHeader>
            <h2 className="text-lg font-semibold text-gray-900">
              Incidents List
            </h2>
          </CardHeader>
          <CardContent className="p-0">
            {loading && incidents.length === 0 ? (
              <div className="px-6 py-10 text-center text-sm text-gray-500">
                Loading incidents...
              </div>
            ) : incidents.length === 0 ? (
              <div className="px-6 py-10 text-center text-sm text-gray-500">
                No incidents found.
              </div>
            ) : (
              <ul className="divide-y divide-gray-100">
                {incidents.map((incident) => (
                  <li
                    key={incident.public_uuid}
                    className="flex flex-col gap-2 px-4 py-4 sm:flex-row sm:items-center sm:justify-between sm:px-6"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${getStatusColor(incident.status_code)}`}>
                          {incident.status_code}
                        </span>
                        <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${getSeverityColor(incident.severity_code)}`}>
                          {incident.severity_code}
                        </span>
                        <span className="text-xs text-gray-500">
                          {incident.incident_code}
                        </span>
                      </div>
                      <p className="mt-1 font-medium text-gray-900">
                        {incident.title}
                      </p>
                      <p className="mt-0.5 text-sm text-gray-600">
                        <span className="font-medium text-gray-700">
                          {incident.category_code}
                        </span>
                        <span className="mx-1.5 text-gray-300">·</span>
                        <span className="text-gray-500">
                          Reported: {formatDate(incident.reported_at)}
                        </span>
                      </p>
                    </div>
                    <div className="flex shrink-0 gap-2">
                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        onClick={() =>
                          router.push(
                            `/dashboard/dispatcher/incidents/${incident.public_uuid}`
                          )
                        }
                      >
                        View Details
                      </Button>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        {pagination.total > pagination.limit && (
          <div className="flex items-center justify-between">
            <Button
              type="button"
              variant="secondary"
              disabled={pagination.offset === 0 || loading}
              onClick={() => void loadIncidents(Math.max(0, pagination.offset - pagination.limit))}
            >
              Previous
            </Button>
            <span className="text-sm text-gray-600">
              Page {Math.floor(pagination.offset / pagination.limit) + 1} of{" "}
              {Math.ceil(pagination.total / pagination.limit)}
            </span>
            <Button
              type="button"
              variant="secondary"
              disabled={
                pagination.offset + pagination.limit >= pagination.total || loading
              }
              onClick={() => void loadIncidents(pagination.offset + pagination.limit)}
            >
              Next
            </Button>
          </div>
        )}
      </div>
    </DashboardLayout>
  );
}
