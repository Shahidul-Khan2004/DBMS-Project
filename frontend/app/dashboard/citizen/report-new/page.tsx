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
import {
  CitizenSectionCard,
  getCitizenFriendlyError,
} from "@/components/citizen/CitizenPortal";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { Button } from "@/components/ui/Button";
import { Input } from "@/components/ui/Input";
import { PageLoading } from "@/components/ui/StatusState";
import { apiPost, ensureAuthSession } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import {
  getCurrentBangladeshDatetimeLocal,
  isValidBangladeshLocalDatetime,
  toBangladeshIsoDatetime,
} from "@/lib/datetime";
import { getMySavedLocations } from "@/lib/locations-api";
import { useAuthGuard } from "@/lib/use-auth-guard";
import type {
  LocationPickerSelectionDetails,
  LocationPickerValue,
} from "@/components/location/LocationPicker";
import type {
  CreateIntakeReportRequest,
  CreateIntakeReportResponse,
} from "@/types/intake";
import type { SavedLocation } from "@/types/locations";

const LocationPicker = dynamic(
  () =>
    import("@/components/location/LocationPicker").then((mod) => ({
      default: mod.LocationPicker,
    })),
  {
    ssr: false,
    loading: () => (
      <div className="h-[220px] animate-pulse rounded-2xl bg-slate-100" />
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
  /** Public UUID submitted as API `locationId` when a saved location is selected. */
  savedLocationId: string;
};

type SubmittedReport = {
  publicUuid?: string;
  reportCode?: string;
};

const REPORT_STEPS = [
  { id: 1, label: "Details" },
  { id: 2, label: "Location" },
  { id: 3, label: "Review" },
] as const;

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
  const [savedLocationsError, setSavedLocationsError] = useState("");
  const [stepError, setStepError] = useState("");
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

  const loadSavedLocations = useCallback(async () => {
    setIsLoadingLocations(true);
    setSavedLocationsError("");
    try {
      const data = await getMySavedLocations();
      setSavedLocations(data.locations);
    } catch (err) {
      console.error("Failed to load saved locations for report form", err);
      setSavedLocations([]);
      setSavedLocationsError(
        "We couldn't load your saved locations. You can still search or select a location manually.",
      );
    } finally {
      setIsLoadingLocations(false);
    }
  }, []);

  useEffect(() => {
    if (isChecking) return;

    void loadSavedLocations();
  }, [isChecking, loadSavedLocations]);

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
      setStepError("");
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
    setStepError("");
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
    setStepError("");
    setSubmittedReport(null);
  };

  const getDetailsValidationMessage = () => {
    if (!form.categoryCode.trim()) {
      return "Choose the incident category before continuing.";
    }

    if (form.summary.trim().length < 6) {
      return "Write a summary with at least 6 characters.";
    }

    if (form.urgencyType !== "unknown" && form.urgencyType !== "non_emergency") {
      return "Citizen reports can only use Unknown or Non-Emergency urgency.";
    }

    if (form.reportedAt && !isValidBangladeshLocalDatetime(form.reportedAt)) {
      return "Reported time must be a valid Bangladesh date and time.";
    }

    return "";
  };

  const getLocationValidationMessage = () => {
    const selectedCoordinates = getSelectedCoordinates(form);

    if (!selectedCoordinates && !form.savedLocationId) {
      return "Choose a report location from search, the map, My location, or a saved location.";
    }

    if (
      selectedCoordinates &&
      (selectedCoordinates.latitude < -90 ||
        selectedCoordinates.latitude > 90 ||
        selectedCoordinates.longitude < -180 ||
        selectedCoordinates.longitude > 180)
    ) {
      return "Choose a valid point on the map before continuing.";
    }

    return "";
  };

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setSubmittedReport(null);

    const detailsValidationMessage = getDetailsValidationMessage();
    if (detailsValidationMessage) {
      setStepError(detailsValidationMessage);
      setMessage(null);
      return;
    }

    const locationValidationMessage = getLocationValidationMessage();
    if (locationValidationMessage) {
      setStepError(locationValidationMessage);
      setMessage(null);
      return;
    }

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

    if (!selectedCoordinates && !form.savedLocationId) {
      setMessage({
        type: "error",
        text: "Choose a report location from search, the map, My location, or a saved location.",
      });
      return;
    }

    if (
      selectedCoordinates &&
      (selectedCoordinates.latitude < -90 ||
        selectedCoordinates.latitude > 90 ||
        selectedCoordinates.longitude < -180 ||
        selectedCoordinates.longitude > 180)
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
        ...(form.savedLocationId
          ? { locationId: form.savedLocationId }
          : selectedCoordinates
            ? {
                location: {
                  latitude: selectedCoordinates.latitude,
                  longitude: selectedCoordinates.longitude,
                  address_text: addr || undefined,
                  place_name: placeName || undefined,
                  source: "user_shared",
                },
              }
            : {}),
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
      setStepError("");
    } catch (err) {
      console.error("Failed to submit citizen report", err);
      setMessage({
        type: "error",
        text: getCitizenFriendlyError(
          err,
          "We could not submit your report right now. Please review the form and try again.",
        ),
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isChecking) {
    return <PageLoading label="Loading report form" />;
  }

  const selectedCoordinates = getSelectedCoordinates(form);
  const selectedSavedLocation = savedLocations.find(
    (location) => location.publicUuid === form.savedLocationId,
  );
  const selectedCategoryLabel =
    CATEGORY_OPTIONS.find((option) => option.value === form.categoryCode)
      ?.label ?? "-";
  const detailsValidationMessage = getDetailsValidationMessage();
  const locationValidationMessage = getLocationValidationMessage();
  const detailsReady = !detailsValidationMessage;
  const locationReady = detailsReady && !locationValidationMessage;
  const canSubmit = detailsReady && locationReady;

  const getStepState = (stepId: number) => {
    if (stepId === 1) return detailsReady ? "complete" : "active";
    if (stepId === 2) {
      if (!detailsReady) return "locked";
      return locationReady ? "complete" : "active";
    }
    if (!locationReady) return "locked";
    return "active";
  };

  return (
    <DashboardLayout
      title="Report New Incident"
      subtitle="Create a report with accurate details so responders can review it quickly."
      onLogout={handleLogout}
    >
      <div className="space-y-3">
        <div className="overflow-x-auto rounded-2xl border border-[#002D62]/10 bg-white px-3 py-2 shadow-sm shadow-[#002D62]/5">
          <div className="flex min-w-max items-center gap-2 sm:min-w-0">
            {REPORT_STEPS.map((step, index) => {
              const state = getStepState(step.id);
              const complete = state === "complete";
              const active = state === "active";
              const locked = state === "locked";

              return (
                <div
                key={step.id}
                  className="flex flex-1 items-center gap-2"
                >
                  <div
                    className={`inline-flex h-8 items-center gap-2 rounded-full px-3 text-xs font-semibold ${
                      complete
                        ? "bg-[#F0F7F4] text-[#006747]"
                        : active
                          ? "bg-[#002D62] text-white"
                          : "bg-slate-100 text-slate-500"
                    }`}
                    aria-current={active ? "step" : undefined}
                    aria-disabled={locked}
              >
                <span
                      className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-xs ${
                        active
                          ? "bg-white text-[#002D62]"
                          : complete
                            ? "bg-[#006747] text-white"
                            : "bg-white text-slate-500"
                  }`}
                >
                      {complete ? (
                        <CheckCircle2 className="h-3.5 w-3.5" aria-hidden />
                      ) : (
                        step.id
                      )}
                </span>
                {step.label}
                  </div>
                  {index < REPORT_STEPS.length - 1 ? (
                    <div
                      className={`h-px w-8 sm:flex-1 ${
                        complete ? "bg-[#006747]/40" : "bg-slate-200"
                      }`}
                      aria-hidden
                    />
                  ) : null}
                </div>
              );
            })}
          </div>
        </div>

        {stepError ? (
          <div className="rounded-2xl border border-[#DA291C]/20 bg-red-50 p-4 text-sm text-red-700">
            <div className="flex gap-3">
              <AlertCircle className="mt-0.5 h-5 w-5 shrink-0" aria-hidden />
              <p className="font-medium">{stepError}</p>
            </div>
          </div>
        ) : null}

        <form
          className="grid items-start gap-3 xl:grid-cols-[minmax(280px,0.9fr)_minmax(380px,1.2fr)_minmax(280px,0.9fr)]"
          onSubmit={handleSubmit}
        >
          <CitizenSectionCard
            title="Incident Details"
            subtitle="Use clear details so NIERS can review the report quickly."
            icon={<ClipboardList className="h-5 w-5" aria-hidden />}
            className="[&_header]:px-4 [&_header]:py-3"
            contentClassName="!p-4 space-y-3"
          >
                  <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-1 2xl:grid-cols-2">
                    <div>
                      <label className="mb-1.5 block text-sm font-medium text-gray-700">
                        Category
                      </label>
                      <select
                        name="categoryCode"
                        value={form.categoryCode}
                        onChange={handleChange}
                        required
                        className="block h-[46px] w-full rounded-xl border border-[#002D62]/20 bg-white px-3 py-2 text-sm text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
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
                      <label className="mb-1.5 block text-sm font-medium text-gray-700">
                        Urgency
                      </label>
                      <select
                        name="urgencyType"
                        value={form.urgencyType}
                        onChange={handleChange}
                        className="block h-[46px] w-full rounded-xl border border-[#002D62]/20 bg-white px-3 py-2 text-sm text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
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
                    <label className="mb-1.5 block text-sm font-medium text-gray-700">
                      Description
                    </label>
                    <textarea
                      name="description"
                      value={form.description}
                      onChange={handleChange}
                      rows={3}
                      placeholder="Add nearby landmarks, risks, affected people, or anything responders should know"
                      className="w-full rounded-xl border border-[#002D62]/20 bg-white px-4 py-3 text-sm text-gray-900 placeholder-gray-500 transition-colors focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                    />
                  </div>

                  <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-1 2xl:grid-cols-2">
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
                      <label className="mb-1.5 block text-sm font-medium text-gray-700">
                        Channel
                      </label>
                      <div className="flex h-[46px] items-center rounded-xl border border-[#002D62]/20 bg-white px-4 text-sm font-medium text-gray-900">
                        Web Portal
                      </div>
                    </div>
                  </div>
          </CitizenSectionCard>

          {detailsReady ? (
            <CitizenSectionCard
              title="Report Location"
              subtitle="Use a saved place, search, current position, or map click."
              icon={<MapPin className="h-5 w-5" aria-hidden />}
              className="[&_header]:px-4 [&_header]:py-3"
              contentClassName="!p-4 space-y-3"
            >
                  <div>
                    <label className="mb-1.5 block text-sm font-medium text-gray-700">
                      Saved Location
                    </label>
                    <select
                      name="savedLocationId"
                      value={form.savedLocationId}
                      onChange={handleChange}
                      disabled={isLoadingLocations || savedLocations.length === 0}
                      className="block h-[46px] w-full rounded-xl border border-[#002D62]/20 bg-white px-3 py-2 text-sm text-gray-900 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35 disabled:bg-gray-50 disabled:text-gray-500"
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
                    {savedLocationsError ? (
                      <div className="mt-3 rounded-xl border border-amber-200 bg-amber-50 px-3 py-3 text-sm text-amber-800">
                        <p>{savedLocationsError}</p>
                        <Button
                          type="button"
                          variant="secondary"
                          size="sm"
                          className="mt-3"
                          onClick={() => void loadSavedLocations()}
                          disabled={isLoadingLocations}
                        >
                          Retry
                        </Button>
                      </div>
                    ) : null}
                  </div>

                  <LocationPicker
                    value={selectedCoordinates}
                    onChange={handleLocationPickerChange}
                    selectedAddress={form.locationAddress}
                    selectedPlaceName={form.locationPlaceName}
                    syncSearchQueryToSelectedLabel={false}
                    embedded
                    embeddedCompact
                    mapClassName="h-[210px] w-full"
                    showSelectionSummary={false}
                  />

                  <div className="grid gap-3 sm:grid-cols-2">
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

                  <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl bg-[#F0F7F4] px-4 py-3 text-sm text-slate-700">
                    <div>
                      {selectedCoordinates ? (
                        <p>Location selected.</p>
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
            </CitizenSectionCard>
          ) : (
            <div className="rounded-2xl border border-dashed border-[#002D62]/20 bg-white/70 p-5 text-sm text-[#42547A]">
              Complete the required incident details to add a location.
            </div>
          )}

          {locationReady ? (
            <CitizenSectionCard
              title="Review and Submit"
              subtitle="Confirm the backend-supported report details before sending."
              icon={<CheckCircle2 className="h-5 w-5" aria-hidden />}
              className="[&_header]:px-4 [&_header]:py-3"
              contentClassName="!p-4 space-y-3"
            >
                <div className="grid gap-3">
                  <div className="rounded-xl border border-[#002D62]/10 bg-[#F6F9FE] p-3">
                    <h3 className="text-sm font-semibold text-[#002D62]">
                      Details
                    </h3>
                    <dl className="mt-2 grid gap-2 sm:grid-cols-2">
                      <div>
                        <dt className="text-xs font-semibold uppercase text-[#42547A]">
                          Category
                        </dt>
                        <dd className="mt-1 text-sm font-medium text-slate-900">
                          {selectedCategoryLabel}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-xs font-semibold uppercase text-[#42547A]">
                          Urgency
                        </dt>
                        <dd className="mt-1 text-sm font-medium text-slate-900">
                          {form.urgencyType.replace(/_/g, " ")}
                        </dd>
                      </div>
                      <div className="sm:col-span-2">
                        <dt className="text-xs font-semibold uppercase text-[#42547A]">
                          Summary
                        </dt>
                        <dd className="mt-1 break-words text-sm font-medium text-slate-900">
                          {form.summary.trim()}
                        </dd>
                      </div>
                      <div className="sm:col-span-2">
                        <dt className="text-xs font-semibold uppercase text-[#42547A]">
                          Description
                        </dt>
                        <dd className="mt-1 whitespace-pre-wrap text-sm text-slate-700">
                          {form.description.trim() || "No description provided."}
                        </dd>
                      </div>
                    </dl>
                  </div>

                  <div className="rounded-xl border border-[#002D62]/10 bg-[#F0F7F4] p-3">
                    <h3 className="text-sm font-semibold text-[#002D62]">
                      Location
                    </h3>
                    <dl className="mt-2 grid gap-2 sm:grid-cols-2">
                      <div>
                        <dt className="text-xs font-semibold uppercase text-[#42547A]">
                          Saved Location
                        </dt>
                        <dd className="mt-1 break-words text-sm font-medium text-slate-900">
                          {selectedSavedLocation
                            ? formatSavedLocation(selectedSavedLocation)
                            : "Map point"}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-xs font-semibold uppercase text-[#42547A]">
                          Reported Time
                        </dt>
                        <dd className="mt-1 text-sm font-medium text-slate-900">
                          {form.reportedAt || "-"}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-xs font-semibold uppercase text-[#42547A]">
                          Address
                        </dt>
                        <dd className="mt-1 break-words text-sm text-slate-700">
                          {form.locationAddress.trim() || "-"}
                        </dd>
                      </div>
                      <div>
                        <dt className="text-xs font-semibold uppercase text-[#42547A]">
                          Place
                        </dt>
                        <dd className="mt-1 break-words text-sm text-slate-700">
                          {form.locationPlaceName.trim() || "-"}
                        </dd>
                      </div>
                    </dl>
                  </div>
                </div>
              <Button
                type="submit"
                isLoading={isSubmitting}
                disabled={!canSubmit}
                className="w-full sm:w-auto"
              >
                Submit Report
              </Button>
            </CitizenSectionCard>
          ) : detailsReady ? (
            <div className="rounded-2xl border border-dashed border-[#002D62]/20 bg-white/70 p-5 text-sm text-[#42547A]">
              Select a valid saved location or map point to review and submit.
            </div>
          ) : null}

          {message ? (
            <div
              className={`rounded-2xl border p-3 text-sm xl:col-span-3 ${
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
                  {message.type === "success" ? (
                    <div className="mt-3 flex flex-wrap gap-2">
                      {submittedReport?.publicUuid ? (
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
                      ) : null}
                      <Button
                        type="button"
                        variant="secondary"
                        size="sm"
                        onClick={() => router.push("/dashboard/citizen/reports")}
                      >
                        My Reports
                      </Button>
                    </div>
                  ) : null}
                </div>
              </div>
            </div>
          ) : null}
        </form>
      </div>
    </DashboardLayout>
  );
}
