"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { clearAuthSession, getValidAccessToken } from "@/lib/auth-store";

const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE_URL ?? "http://localhost:8080";

type Mode = "standalone" | "intake";
type IncidentCreatePayload =
  | {
      severityCode: string;
      intakeReportPublicUuid: string;
      title?: string;
      description?: string;
      reportedAt?: string;
    }
  | {
      categoryCode: string;
      severityCode: string;
      title: string;
      description?: string;
      reportedAt?: string;
      location: {
        latitude: number;
        longitude: number;
        address_text: string;
        source: "manual_entry";
      };
    };

const labelClassName = "block text-sm font-medium text-gray-700";
const fieldClassName =
  "mt-1 w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-gray-900 placeholder-gray-400";

export default function CreateEmergencyIncidentPage() {
  const router = useRouter();

  const [mode, setMode] = useState<Mode>("standalone");
  const [categoryCode, setCategoryCode] = useState("medical");
  const [severityCode, setSeverityCode] = useState("high");
  const [intakeReportPublicUuid, setIntakeReportPublicUuid] = useState("");
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [reportedAt, setReportedAt] = useState("");
  const [location, setLocation] = useState("");
  const [latitude, setLatitude] = useState("");
  const [longitude, setLongitude] = useState("");

  const [isLoadingSession, setIsLoadingSession] = useState(true);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const redirectToLogin = useCallback(() => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/auth/login");
  }, [router]);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const requestedMode = params.get("mode");
    const requestedIntakeUuid = params.get("intakeReportPublicUuid");

    if (requestedMode === "intake") {
      setMode("intake");
    }

    if (requestedIntakeUuid) {
      setIntakeReportPublicUuid(requestedIntakeUuid);
    }
  }, []);

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

      const reportedAtIso = reportedAt
        ? new Date(reportedAt).toISOString()
        : undefined;

      const body: IncidentCreatePayload =
        mode === "intake"
          ? {
              severityCode,
              intakeReportPublicUuid: intakeReportPublicUuid.trim(),
              title: title || undefined,
              description: description || undefined,
              reportedAt: reportedAtIso,
            }
          : {
              categoryCode,
              severityCode,
              title: title.trim(),
              description: description || undefined,
              reportedAt: reportedAtIso,
              location: {
                latitude: Number(latitude),
                longitude: Number(longitude),
                address_text: location.trim(),
                source: "manual_entry",
              },
            };

      const res = await fetch(`${API_BASE}/operations/incidents`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(body),
      });

      const data = await res.json().catch(() => ({}));

      if (!res.ok) {
        throw new Error(
          data?.error?.message ||
            data?.message ||
            data?.code ||
            "Incident creation failed",
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
      title="Create Emergency Incident"
      subtitle="Create a standalone incident or link an existing intake report"
      onLogout={handleLogout}
    >
      <div className="mx-auto max-w-3xl space-y-6">
        <Card>
          <CardHeader>
            <h1 className="text-2xl font-bold text-gray-900">
              Create Emergency Incident
            </h1>
            <p className="text-sm text-gray-500">
              Create a standalone incident or link an existing intake report.
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
                <label className={labelClassName}>Create Mode</label>
                <select
                  value={mode}
                  onChange={(e) => setMode(e.target.value as Mode)}
                  className={fieldClassName}
                >
                  <option value="standalone">Standalone Incident</option>
                  <option value="intake">Link Existing Intake</option>
                </select>
              </div>

              {mode === "intake" && (
                <div>
                  <label className={labelClassName}>
                    Intake Report Public UUID
                  </label>
                  <input
                    value={intakeReportPublicUuid}
                    onChange={(e) => setIntakeReportPublicUuid(e.target.value)}
                    required
                    className={fieldClassName}
                    placeholder="0d5fd834-a3fc-4180-b8ec-a6e664d130d0"
                  />
                </div>
              )}

              {mode === "standalone" && (
                <div>
                  <label className={labelClassName}>Category</label>
                  <select
                    value={categoryCode}
                    onChange={(e) => setCategoryCode(e.target.value)}
                    className={fieldClassName}
                  >
                    <option value="medical">Medical</option>
                    <option value="fire">Fire</option>
                    <option value="crime_public_safety">Crime / Public Safety</option>
                    <option value="natural_disaster">Natural Disaster</option>
                    <option value="infrastructure_emergency">Infrastructure Emergency</option>
                    <option value="relief_request">Relief Request</option>
                    <option value="blood_request">Blood Request</option>
                  </select>
                </div>
              )}

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
                <label className={labelClassName}>Title</label>
                <input
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  required={mode === "standalone"}
                  className={fieldClassName}
                  placeholder="Worker collapsed near loading dock"
                />
              </div>

              <div>
                <label className={labelClassName}>Description</label>
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  className={fieldClassName}
                  rows={4}
                  placeholder="On-site medic requested immediate ambulance dispatch."
                />
              </div>

              <div>
                <label className={labelClassName}>Reported At</label>
                <input
                  type="datetime-local"
                  value={reportedAt}
                  onChange={(e) => setReportedAt(e.target.value)}
                  className={fieldClassName}
                />
              </div>

              {mode === "standalone" && (
                <>
                  <div>
                    <label className={labelClassName}>Location</label>
                    <input
                      value={location}
                      onChange={(e) => setLocation(e.target.value)}
                      required
                      className={fieldClassName}
                      placeholder="House 12, Road 3, Dhanmondi, Dhaka"
                    />
                  </div>
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div>
                      <label className={labelClassName}>Latitude</label>
                      <input
                        type="number"
                        step="any"
                        value={latitude}
                        onChange={(e) => setLatitude(e.target.value)}
                        required
                        className={fieldClassName}
                        placeholder="23.8103"
                      />
                    </div>
                    <div>
                      <label className={labelClassName}>Longitude</label>
                      <input
                        type="number"
                        step="any"
                        value={longitude}
                        onChange={(e) => setLongitude(e.target.value)}
                        required
                        className={fieldClassName}
                        placeholder="90.4125"
                      />
                    </div>
                  </div>
                </>
              )}

              <div className="flex gap-3">
                <Button type="submit" disabled={loading}>
                  {loading ? "Creating..." : "Create Incident"}
                </Button>

                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => router.push("/dashboard/dispatcher/incidents")}
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
