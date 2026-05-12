"use client";

import dynamic from "next/dynamic";
import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardHeader, CardContent } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { PageHeader, PageLoading } from "@/components/ui/StatusState";
import { ApiError, apiPost, ensureAuthSession } from "@/lib/api";
import {
  getCurrentBangladeshDatetimeLocal,
  isValidBangladeshLocalDatetime,
  toBangladeshIsoDatetime,
} from "@/lib/datetime";
import { clearAuthSession } from "@/lib/auth-store";
import type {
  LocationPickerSelectionDetails,
  LocationPickerValue,
} from "@/components/location/LocationPicker";

const LocationPicker = dynamic(
  () =>
    import("@/components/location/LocationPicker").then((mod) => ({
      default: mod.LocationPicker,
    })),
  {
    ssr: false,
    loading: () => (
      <div className="h-[420px] animate-pulse rounded-2xl bg-slate-100" />
    ),
  },
);

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
        place_name?: string;
        source: "dispatcher_selected";
      };
    };

type IncidentCreateResponse = {
  incident: {
    public_uuid: string;
  };
};

const labelClassName = "block text-sm font-medium text-gray-700";
const fieldClassName =
  "mt-1 w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-gray-900 placeholder-gray-400 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35";
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

type SelectedLocation = {
  latitude: number;
  longitude: number;
};

function formatApiError(error: unknown, fallback: string) {
  if (error instanceof ApiError) {
    const hints: Record<string, string> = {
      CATEGORY_REQUIRED: "Choose a category for standalone incidents.",
      LOCATION_REQUIRED: "Choose a map point before creating a standalone incident.",
      INCIDENT_TITLE_REQUIRED: "Add a title for this standalone incident.",
      INCIDENT_SEVERITY_NOT_FOUND: "Choose one of the supported severity levels.",
      REPORT_CATEGORY_NOT_FOUND: "Choose one of the supported incident categories.",
      EMERGENCY_INCIDENT_REQUIRES_LOCATION:
        "The selected intake report needs a reported location before it can create an incident.",
      INTAKE_ALREADY_LINKED:
        "This intake report is already linked to an emergency incident.",
      INTAKE_NOT_PROMOTABLE:
        "This intake report cannot create an incident in its current status.",
    };
    const hint = error.code ? hints[error.code] : undefined;
    const codePrefix = error.code ? `${error.code}: ` : "";
    return `${codePrefix}${error.message}${hint ? ` ${hint}` : ""}`;
  }

  return error instanceof Error ? error.message : fallback;
}

export default function CreateEmergencyIncidentPage() {
  const router = useRouter();
  const defaultReportedAtRef = useRef(getCurrentBangladeshDatetimeLocal());

  const [mode, setMode] = useState<Mode>("standalone");
  const [categoryCode, setCategoryCode] = useState("medical");
  const [severityCode, setSeverityCode] = useState("high");
  const [intakeReportPublicUuid, setIntakeReportPublicUuid] = useState("");
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [reportedAt, setReportedAt] = useState(defaultReportedAtRef.current);
  const [locationAddress, setLocationAddress] = useState("");
  const [locationPlaceName, setLocationPlaceName] = useState("");
  const [selectedLocation, setSelectedLocation] =
    useState<SelectedLocation | null>(null);

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

  const handleLocationChange = useCallback(
    (
      location: LocationPickerValue,
      details?: LocationPickerSelectionDetails,
    ) => {
      setSelectedLocation({
        latitude: location.latitude,
        longitude: location.longitude,
      });
      setLocationAddress((current) => details?.addressText ?? current);
      setLocationPlaceName((current) => details?.placeName ?? current);
      setError("");
    },
    [],
  );

  const clearSelectedLocation = () => {
    setSelectedLocation(null);
    setLocationAddress("");
    setLocationPlaceName("");
  };

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");

    try {
      const token = await ensureAuthSession();

      if (!token) {
        redirectToLogin();
        return;
      }

      if (reportedAt && !isValidBangladeshLocalDatetime(reportedAt)) {
        setError("Reported time must be a valid Bangladesh date and time.");
        return;
      }

      const titleText = title.trim();
      const descriptionText = description.trim();
      const intakeUuid = intakeReportPublicUuid.trim();
      const standaloneLocation = selectedLocation;
      const addressText =
        locationAddress.trim() ||
        locationPlaceName.trim() ||
        titleText ||
        "Dispatcher selected incident location";
      const placeName = locationPlaceName.trim();
      const reportedAtPayload = toBangladeshIsoDatetime(reportedAt);

      if (mode === "intake") {
        if (!UUID_PATTERN.test(intakeUuid)) {
          setError("Enter a valid intake report public UUID.");
          return;
        }
      } else {
        if (!categoryCode.trim()) {
          setError("Choose a category for the standalone incident.");
          return;
        }

        if (!titleText) {
          setError("Add a title for the standalone incident.");
          return;
        }

        if (!standaloneLocation) {
          setError("Choose an incident location from search or the map.");
          return;
        }

        if (addressText.length > 255) {
          setError("Location address must be 255 characters or fewer.");
          return;
        }

        if (placeName.length > 150) {
          setError("Place name must be 150 characters or fewer.");
          return;
        }
      }

      setLoading(true);

      let body: IncidentCreatePayload;

      if (mode === "intake") {
        body = {
          severityCode,
          intakeReportPublicUuid: intakeUuid,
          title: titleText || undefined,
          description: descriptionText || undefined,
          reportedAt: reportedAtPayload,
        };
      } else {
        if (!standaloneLocation) {
          setError("Choose an incident location from search or the map.");
          return;
        }

        body = {
          categoryCode,
          severityCode,
          title: titleText,
          description: descriptionText || undefined,
          reportedAt: reportedAtPayload,
          location: {
            latitude: standaloneLocation.latitude,
            longitude: standaloneLocation.longitude,
            address_text: addressText,
            place_name: placeName || undefined,
            source: "dispatcher_selected",
          },
        };
      }

      const data = await apiPost<IncidentCreateResponse, IncidentCreatePayload>(
        "/operations/incidents",
        body,
      );

      router.push(`/dashboard/dispatcher/incidents/${data.incident.public_uuid}`);
    } catch (err) {
      setError(formatApiError(err, "Incident creation failed."));
    } finally {
      setLoading(false);
    }
  }

  if (isLoadingSession) {
    return <PageLoading label="Loading incident form" />;
  }

  return (
    <DashboardLayout
      title="Create Emergency Incident"
      subtitle="Create a standalone incident or link an existing intake report"
      onLogout={handleLogout}
    >
      <div className="mx-auto max-w-screen-xl space-y-6">
        <PageHeader
          eyebrow="Emergency operations"
          title="Create Emergency Incident"
          description="Add incident facts, then choose the dispatch location on the map when creating a standalone incident."
        />

        {error && <ErrorAlert message={error} />}

        <form
          onSubmit={handleSubmit}
          className="grid gap-6 xl:grid-cols-[minmax(0,0.92fr)_minmax(480px,1.08fr)]"
        >
          <Card className="shadow-md">
            <CardHeader>
              <h2 className="text-lg font-semibold text-[#002D62]">
                Incident Details
              </h2>
              <p className="mt-1 text-sm text-gray-600">
                Classification, severity, summary, and timing.
              </p>
            </CardHeader>

            <CardContent className="space-y-4">
              <div>
                <label className={labelClassName}>Create Mode</label>
                <select
                  value={mode}
                  onChange={(e) => {
                    setMode(e.target.value as Mode);
                    setError("");
                  }}
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
                    onChange={(e) => {
                      setIntakeReportPublicUuid(e.target.value);
                      setError("");
                    }}
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
                  rows={5}
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

              <div className="flex flex-wrap gap-3 pt-2">
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
            </CardContent>
          </Card>

          <Card className="shadow-md xl:sticky xl:top-6">
            <CardHeader>
              <h2 className="text-lg font-semibold text-[#002D62]">
                Location Map
              </h2>
              <p className="mt-1 text-sm text-gray-600">
                Search by place name or click the exact incident point.
              </p>
            </CardHeader>

            <CardContent className="space-y-4">
              {mode === "standalone" ? (
                <>
                  <div className="grid gap-4 md:grid-cols-2">
                    <div>
                      <label className={labelClassName}>
                        Location Name or Address
                      </label>
                      <input
                        value={locationAddress}
                        onChange={(e) => {
                          setLocationAddress(e.target.value);
                          setError("");
                        }}
                        required
                        className={fieldClassName}
                        placeholder="House 12, Road 3, Dhanmondi, Dhaka"
                      />
                    </div>

                    <div>
                      <label className={labelClassName}>Place Name</label>
                      <input
                        value={locationPlaceName}
                        onChange={(e) => {
                          setLocationPlaceName(e.target.value);
                          setError("");
                        }}
                        className={fieldClassName}
                        placeholder="Gate, building, landmark, or area"
                      />
                    </div>
                  </div>

                  <LocationPicker
                    value={selectedLocation}
                    onChange={handleLocationChange}
                    selectedAddress={locationAddress}
                    selectedPlaceName={locationPlaceName}
                  />

                  <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl bg-white px-4 py-3 text-sm text-slate-700">
                    <p>
                      {selectedLocation
                        ? "Map location is ready for this incident."
                        : "Choose a map point before creating the incident."}
                    </p>
                    <Button
                      type="button"
                      variant="secondary"
                      size="sm"
                      onClick={clearSelectedLocation}
                      disabled={!selectedLocation || loading}
                    >
                      Clear Location
                    </Button>
                  </div>
                </>
              ) : (
                <div className="rounded-2xl bg-[#EFF6FF] p-4 text-sm leading-6 text-slate-700">
                  This incident will use the category and reported location from
                  the selected intake report. No separate map point is needed.
                </div>
              )}
            </CardContent>
          </Card>
        </form>
      </div>
    </DashboardLayout>
  );
}
