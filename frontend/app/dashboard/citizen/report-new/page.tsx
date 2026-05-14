"use client";

import dynamic from "next/dynamic";
import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { useRouter } from "next/navigation";
import {
  AlertCircle,
  CalendarClock,
  CheckCircle2,
  ClipboardList,
  MapPin,
} from "lucide-react";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Card, CardContent, CardHeader } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { PageHeader, PageLoading } from "@/components/ui/StatusState";
import { apiJson, apiPost, ensureAuthSession } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import {
  getCurrentBangladeshDatetimeLocal,
  isValidBangladeshLocalDatetime,
  toBangladeshIsoDatetime,
} from "@/lib/datetime";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type {
  LocationPickerSelectionDetails,
  LocationPickerValue,
} from "@/components/location/LocationPicker";
import type {
  CreateIntakeReportRequest,
  CreateIntakeReportResponse,
} from "@/types/intake";
import type { SavedLocation, SavedLocationsResponse } from "@/types/locations";

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

const CATEGORY_OPTIONS = [
  { value: "medical", label: "Medical" },
  { value: "crime_public_safety", label: "Crime / Public Safety" },
  { value: "fire", label: "Fire" },
  { value: "natural_disaster", label: "Natural Disaster" },
  { value: "infrastructure_emergency", label: "Infrastructure Emergency" },
  { value: "relief_request", label: "Relief Request" },
  { value: "blood_request", label: "Blood Request" },
] as const;

type ReportFormState = {
  categoryCode: string;
  summary: string;
  description: string;
  urgencyType: "non_emergency" | "unknown";
  reportedAt: string;
  /** WGS84 degrees from map or geolocation */
  latitude: number | null;
  longitude: number | null;
  /** Maps to API `address_text` when submitting structured location */
  locationAddress: string;
  /** Maps to API `place_name` when submitting structured location */
  locationPlaceName: string;
  /** UI-only saved location selector. The POST payload still sends structured location. */
  savedLocationId: string;
};

type SubmittedReport = {
  publicUuid?: string;
  reportCode?: string;
};

function formatSavedLocation(location: SavedLocation) {
  return (
    location.placeName ||
    location.addressText ||
    "Saved map location"
  );
}

function getSelectedCoordinates(form: ReportFormState) {
  if (form.latitude === null || form.longitude === null) {
    return null;
  }

  if (!Number.isFinite(form.latitude) || !Number.isFinite(form.longitude)) {
    return null;
  }

  return {
    latitude: form.latitude,
    longitude: form.longitude,
  };
}

export default function CitizenNewReportPage() {
  const router = useRouter();
  const isChecking = useAuthGuard(["citizen"]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isLoadingLocations, setIsLoadingLocations] = useState(true);
  const [message, setMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);
  const [submittedReport, setSubmittedReport] =
    useState<SubmittedReport | null>(null);
  const [savedLocations, setSavedLocations] = useState<SavedLocation[]>([]);

  const [form, setForm] = useState<ReportFormState>({
    categoryCode: "",
    summary: "",
    description: "",
    urgencyType: "unknown",
    reportedAt: getCurrentBangladeshDatetimeLocal(),
    latitude: null,
    longitude: null,
    locationAddress: "",
    locationPlaceName: "",
    savedLocationId: "",
  });

  useEffect(() => {
    if (isChecking) return;

    setIsLoadingLocations(true);
    void apiJson<SavedLocationsResponse>("/locations/my")
      .then((data) => setSavedLocations(data.locations ?? []))
      .catch(() => setSavedLocations([]))
      .finally(() => setIsLoadingLocations(false));
  }, [isChecking]);

  const handleLocationPickerChange = useCallback(
    (
      location: LocationPickerValue,
      details?: LocationPickerSelectionDetails,
    ) => {
      setForm((prev) => ({
        ...prev,
        latitude: location.latitude,
        longitude: location.longitude,
        locationAddress: details?.addressText ?? "",
        locationPlaceName: details?.placeName ?? "",
        savedLocationId: "",
      }));
      setMessage(null);
      setSubmittedReport(null);
    },
    [],
  );

  const clearMapLocation = () => {
    setForm((prev) => ({
      ...prev,
      latitude: null,
      longitude: null,
      locationAddress: "",
      locationPlaceName: "",
      savedLocationId: "",
    }));
    setSubmittedReport(null);
  };

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  const handleChange = (
    e: React.ChangeEvent<
      HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement
    >,
  ) => {
    const { name, value } = e.target;
    setForm((prev) => {
      if (name === "savedLocationId") {
        const selectedLocation = savedLocations.find(
          (location) => location.publicUuid === value,
        );

        if (!selectedLocation) {
          return {
            ...prev,
            savedLocationId: "",
          };
        }

        return {
          ...prev,
          savedLocationId: selectedLocation.publicUuid,
          latitude: selectedLocation.latitude,
          longitude: selectedLocation.longitude,
          locationAddress: selectedLocation.addressText ?? "",
          locationPlaceName: selectedLocation.placeName ?? "",
        };
      }

      return {
        ...prev,
        [name]: value,
      };
    });
    setSubmittedReport(null);
  };

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setSubmittedReport(null);

    const summary = form.summary.trim();
    const description = form.description.trim();
    const addr = form.locationAddress.trim();
    const placeName = form.locationPlaceName.trim();
    const selectedCoordinates = getSelectedCoordinates(form);

    if (summary.length < 6) {
      setMessage({
        type: "error",
        text: "Summary must be at least 6 characters.",
      });
      return;
    }

    if (!form.categoryCode.trim()) {
      setMessage({ type: "error", text: "Please select a category." });
      return;
    }

    if (form.urgencyType !== "unknown" && form.urgencyType !== "non_emergency") {
      setMessage({
        type: "error",
        text: "Citizen reports can only use Unknown or Non-Emergency urgency.",
      });
      return;
    }

    if (!selectedCoordinates) {
      setMessage({
        type: "error",
        text: "Choose a report location from search, the map, My location, or a saved location.",
      });
      return;
    }

    if (
      selectedCoordinates.latitude < -90 ||
        selectedCoordinates.latitude > 90 ||
        selectedCoordinates.longitude < -180 ||
      selectedCoordinates.longitude > 180
    ) {
      setMessage({
        type: "error",
        text: "Choose a valid point on the map before submitting.",
      });
      return;
    }

    if (form.reportedAt && !isValidBangladeshLocalDatetime(form.reportedAt)) {
      setMessage({
        type: "error",
        text: "Reported time must be a valid Bangladesh date and time.",
      });
      return;
    }

    const accessToken = await ensureAuthSession();
    if (!accessToken) {
      router.push("/auth/login");
      return;
    }

    setIsSubmitting(true);
    setMessage(null);

    try {
      const payload: CreateIntakeReportRequest = {
        channelCode: "web_portal",
        categoryCode: form.categoryCode,
        summary,
        description: description || undefined,
        urgencyType: form.urgencyType,
        reportedAt: toBangladeshIsoDatetime(form.reportedAt),
        location: {
          latitude: selectedCoordinates.latitude,
          longitude: selectedCoordinates.longitude,
          address_text: addr || undefined,
          place_name: placeName || undefined,
          source: "user_shared",
        },
      };

      const data = await apiPost<
        CreateIntakeReportResponse,
        CreateIntakeReportRequest
      >("/intake/reports", payload);

      setMessage({
        type: "success",
        text: `Report submitted successfully. Reference: ${data.intake.report_code}`,
      });
      setSubmittedReport({
        publicUuid: data.intake.public_uuid,
        reportCode: data.intake.report_code,
      });

      setForm({
        categoryCode: "",
        summary: "",
        description: "",
        urgencyType: "unknown",
        reportedAt: getCurrentBangladeshDatetimeLocal(),
        latitude: null,
        longitude: null,
        locationAddress: "",
        locationPlaceName: "",
        savedLocationId: "",
      });
    } catch (err) {
      setMessage({
        type: "error",
        text:
          err instanceof Error
            ? err.message
            : "Unexpected error while submitting report.",
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isChecking) {
    return <PageLoading label="Loading report form" />;
  }

  const selectedCoordinates = getSelectedCoordinates(form);

  return (
    <DashboardLayout
      title="Report New Incident"
      subtitle="Create an intake report for the NIERS team"
      onLogout={handleLogout}
    >
      <div className="space-y-6">
        <PageHeader
          eyebrow="Citizen report"
          title="Submit a report with an exact location"
          description="Pick a point on the map, use your current position, or choose a saved place. The backend receives the structured location data."
          actions={
            <Button
              type="button"
              variant="secondary"
              onClick={() => router.push("/dashboard/citizen")}
            >
              Back to Dashboard
            </Button>
          }
        />

        <Card className="shadow-md">
          <CardHeader>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#002D62] text-white">
                <ClipboardList className="h-5 w-5" aria-hidden />
              </div>
              <div>
                <h2 className="text-lg font-semibold text-[#002D62]">
                  Incident Report Form
                </h2>
                <p className="mt-1 text-sm text-gray-600">
                  Required fields are summary, category, urgency, and location.
                </p>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <form
              className="grid items-start gap-6 xl:grid-cols-[minmax(360px,0.9fr)_minmax(520px,1.1fr)]"
              onSubmit={handleSubmit}
            >
              <div className="space-y-5">
              {message && (
                <div
                  className={`rounded-2xl border p-4 text-sm ${
                    message.type === "success"
                      ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                      : "border-[#DA291C]/20 bg-red-50 text-red-700"
                  }`}
                >
                  <div className="flex gap-3">
                    {message.type === "success" ? (
                      <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0" aria-hidden />
                    ) : (
                      <AlertCircle className="mt-0.5 h-5 w-5 shrink-0" aria-hidden />
                    )}
                    <div>
                      <p className="font-medium">{message.text}</p>
                      {message.type === "success" && (
                        <div className="mt-3 flex flex-wrap gap-2">
                          {submittedReport?.publicUuid && (
                            <Button
                              type="button"
                              size="sm"
                              onClick={() =>
                                router.push(
                                  `/dashboard/citizen/reports/${submittedReport.publicUuid}`,
                                )
                              }
                            >
                              View Report Details
                            </Button>
                          )}
                          <Button
                            type="button"
                            variant="secondary"
                            size="sm"
                            onClick={() => router.push("/dashboard/citizen/reports")}
                          >
                            My Reports
                          </Button>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              <div className="grid gap-4 sm:grid-cols-2">
                <div>
                  <label className="mb-2 block text-sm font-medium text-gray-700">
                    Category
                  </label>
                  <select
                    name="categoryCode"
                    value={form.categoryCode}
                    onChange={handleChange}
                    required
                    className="block h-[46px] w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-sm text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                  >
                    <option value="" disabled>
                      Select category
                    </option>
                    {CATEGORY_OPTIONS.map((option) => (
                      <option key={option.value} value={option.value}>
                        {option.label}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="mb-2 block text-sm font-medium text-gray-700">
                    Urgency
                  </label>
                  <select
                    name="urgencyType"
                    value={form.urgencyType}
                    onChange={handleChange}
                    className="block h-[46px] w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-sm text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                  >
                    <option value="unknown">Unknown</option>
                    <option value="non_emergency">Non-Emergency</option>
                  </select>
                </div>
              </div>

              <Input
                name="summary"
                label="Summary"
                value={form.summary}
                onChange={handleChange}
                placeholder="Briefly describe what happened"
                required
              />

              <div>
                <label className="mb-2 block text-sm font-medium text-gray-700">
                  Description
                </label>
                <textarea
                  name="description"
                  value={form.description}
                  onChange={handleChange}
                  rows={5}
                  placeholder="Add nearby landmarks, risks, affected people, or anything responders should know"
                  className="w-full rounded-2xl border border-[#002D62]/20 bg-white px-4 py-3 text-sm text-gray-900 placeholder-gray-500 transition-colors focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                />
              </div>

              <div className="grid gap-4 sm:grid-cols-2">
                <Input
                  type="datetime-local"
                  name="reportedAt"
                  label="Reported Time"
                  value={form.reportedAt}
                  onChange={handleChange}
                  icon={<CalendarClock className="h-4 w-4" aria-hidden />}
                  helpText="Defaults to the current time; adjust if needed."
                />
                <div>
                  <label className="mb-2 block text-sm font-medium text-gray-700">
                    Channel
                  </label>
                  <div className="flex h-[46px] items-center rounded-2xl border border-[#002D62]/20 bg-white px-4 text-sm font-medium text-gray-900">
                    Web Portal
                  </div>
                </div>
              </div>

              <div className="flex flex-col gap-3 sm:flex-row">
                <Button
                  type="submit"
                  isLoading={isSubmitting}
                  className="sm:w-auto"
                >
                  Submit Report
                </Button>
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => router.push("/dashboard/citizen/reports")}
                  className="sm:w-auto"
                >
                  View My Reports
                </Button>
              </div>
              </div>

              <div className="space-y-5">
                <div className="rounded-3xl border border-[#002D62]/10 bg-white p-5 shadow-sm">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-[#006747] text-white">
                        <MapPin className="h-5 w-5" aria-hidden />
                      </div>
                      <div>
                        <h3 className="font-semibold text-[#002D62]">
                          Report Location
                        </h3>
                        <p className="mt-1 text-sm text-gray-600">
                          Search, click the map, or use your current position.
                        </p>
                      </div>
                    </div>
                  </div>

                  <div className="mt-4 space-y-4">
                    <div>
                      <label className="mb-2 block text-sm font-medium text-gray-700">
                        Saved Location
                      </label>
                      <select
                        name="savedLocationId"
                        value={form.savedLocationId}
                        onChange={handleChange}
                        disabled={isLoadingLocations || savedLocations.length === 0}
                        className="block h-[46px] w-full rounded-2xl border border-[#002D62]/20 bg-white px-3 py-2 text-sm text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35 disabled:bg-gray-50 disabled:text-gray-500"
                      >
                        <option value="">
                          {isLoadingLocations
                            ? "Loading saved locations..."
                            : savedLocations.length > 0
                              ? "Use map point instead"
                              : "No saved locations yet"}
                        </option>
                        {savedLocations.map((location) => (
                          <option
                            key={location.publicUuid}
                            value={location.publicUuid}
                          >
                            {formatSavedLocation(location)}
                          </option>
                        ))}
                      </select>
                    </div>

                    <LocationPicker
                      value={selectedCoordinates}
                      onChange={handleLocationPickerChange}
                      selectedAddress={form.locationAddress}
                      selectedPlaceName={form.locationPlaceName}
                      syncSearchQueryToSelectedLabel={false}
                    />

                    <div className="grid gap-4 sm:grid-cols-2">
                      <Input
                        name="locationAddress"
                        label="Address Text"
                        value={form.locationAddress}
                        onChange={handleChange}
                        placeholder="Optional address or landmark"
                        helpText="Optional. A map selection can also fill this."
                      />
                      <Input
                        name="locationPlaceName"
                        label="Place Name"
                        value={form.locationPlaceName}
                        onChange={handleChange}
                        placeholder="Optional place label"
                      />
                    </div>

                    <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl bg-[#EFF6FF] px-4 py-3 text-sm text-slate-700">
                      <div>
                        {selectedCoordinates ? (
                          <p>Map location selected.</p>
                        ) : (
                          <p>Choose a point on the map before submitting.</p>
                        )}
                      </div>
                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        onClick={clearMapLocation}
                        disabled={!selectedCoordinates}
                      >
                        Clear
                      </Button>
                    </div>
                  </div>
                </div>
              </div>
            </form>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  );
}
