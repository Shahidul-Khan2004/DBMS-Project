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
  CitizenPageContent,
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
  const [formError, setFormError] = useState("");
  const [message, setMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);
  const [submittedReport, setSubmittedReport] =
    useState<SubmittedReport | null>(null);
  const [step, setStep] = useState<"form" | "review">("form");
  const [savedLocations, setSavedLocations] = useState<SavedLocation[]>([]);
  const [selectedLocationDetails, setSelectedLocationDetails] =
    useState<LocationPickerSelectionDetails>({});

  const [form, setForm] = useState<ReportFormState>({
    categoryCode: "",
    summary: "",
    description: "",
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
      setSelectedLocationDetails(details ?? {});
      setForm((prev) => {
        const locationChanged =
          prev.latitude !== location.latitude ||
          prev.longitude !== location.longitude;

        return {
          ...prev,
          latitude: location.latitude,
          longitude: location.longitude,
          locationAddress: locationChanged ? "" : prev.locationAddress,
          locationPlaceName: locationChanged ? "" : prev.locationPlaceName,
          savedLocationId: "",
        };
      });
      setMessage(null);
      setFormError("");
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
    setSelectedLocationDetails({});
    setFormError("");
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
    if (name === "savedLocationId") {
      const selectedLocation = savedLocations.find(
        (location) => location.publicUuid === value,
      );

      if (selectedLocation) {
        setSelectedLocationDetails({
          addressText: selectedLocation.addressText ?? undefined,
          placeName: selectedLocation.placeName ?? undefined,
        });
      }
    }

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
          locationAddress: "",
          locationPlaceName: "",
        };
      }

      return {
        ...prev,
        [name]: value,
      };
    });
    setFormError("");
    setSubmittedReport(null);
  };

  const getDetailsValidationMessage = () => {
    if (!form.categoryCode.trim()) {
      return "Choose the incident category before continuing.";
    }

    if (form.summary.trim().length < 6) {
      return "Write a summary with at least 6 characters.";
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

  const handleContinueToReview = () => {
    const detailsValidationMessage = getDetailsValidationMessage();
    if (detailsValidationMessage) {
      setFormError(detailsValidationMessage);
      setMessage(null);
      return;
    }

    const locationValidationMessage = getLocationValidationMessage();
    if (locationValidationMessage) {
      setFormError(locationValidationMessage);
      setMessage(null);
      return;
    }

    setFormError("");
    setMessage(null);
    setStep("review");
  };

  const handleSubmit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setSubmittedReport(null);

    const detailsValidationMessage = getDetailsValidationMessage();
    if (detailsValidationMessage) {
      setFormError(detailsValidationMessage);
      setMessage(null);
      return;
    }

    const locationValidationMessage = getLocationValidationMessage();
    if (locationValidationMessage) {
      setFormError(locationValidationMessage);
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
        reportedAt: getCurrentBangladeshDatetimeLocal(),
        latitude: null,
        longitude: null,
        locationAddress: "",
        locationPlaceName: "",
        savedLocationId: "",
      });
      setSelectedLocationDetails({});
      setFormError("");
      setStep("form");
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
  const selectedLocationLabel =
    form.locationAddress.trim() ||
    selectedLocationDetails.addressText?.trim() ||
    form.locationPlaceName.trim() ||
    selectedLocationDetails.placeName?.trim() ||
    (selectedSavedLocation
      ? formatSavedLocation(selectedSavedLocation)
      : "Selected map point");
  const selectedPlaceName =
    form.locationPlaceName.trim() ||
    selectedLocationDetails.placeName?.trim() ||
    "";
  const showDistinctPlaceName =
    Boolean(selectedPlaceName) && selectedPlaceName !== selectedLocationLabel;
  const selectedCategoryLabel =
    CATEGORY_OPTIONS.find((option) => option.value === form.categoryCode)
      ?.label ?? "-";
  const detailsValidationMessage = getDetailsValidationMessage();
  const locationValidationMessage = getLocationValidationMessage();
  const detailsReady = !detailsValidationMessage;
  const locationReady = detailsReady && !locationValidationMessage;
  const canSubmit = detailsReady && locationReady;

  return (
    <DashboardLayout
      title="Report New Incident"
      subtitle="Share what happened so NIERS can review your report."
      onLogout={handleLogout}
    >
      <CitizenPageContent>
        {formError ? (
          <div className="rounded-2xl border border-[#DA291C]/20 bg-red-50 p-4 text-sm text-red-700">
            <div className="flex gap-3">
              <AlertCircle className="mt-0.5 h-5 w-5 shrink-0" aria-hidden />
              <p className="font-medium">{formError}</p>
            </div>
          </div>
        ) : null}

        {step === "review" ? (
          <form className="space-y-6" onSubmit={handleSubmit}>
            <CitizenSectionCard
              title="Review Your Report"
              subtitle="Review your report before sending it to NIERS."
              icon={<CheckCircle2 className="h-5 w-5" aria-hidden />}
            >
              <div className="grid gap-4 lg:grid-cols-2">
                <div className="rounded-xl border border-slate-200/80 bg-[#F6F9FE] p-4">
                  <h3 className="text-sm font-semibold text-[#002D62]">
                    Incident Details
                  </h3>
                  <dl className="mt-3 space-y-3">
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
                        Summary
                      </dt>
                      <dd className="mt-1 break-words text-sm font-medium text-slate-900">
                        {form.summary.trim()}
                      </dd>
                    </div>
                    <div>
                      <dt className="text-xs font-semibold uppercase text-[#42547A]">
                        Description
                      </dt>
                      <dd className="mt-1 whitespace-pre-wrap text-sm text-slate-700">
                        {form.description.trim() || "No description provided."}
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
                  </dl>
                </div>

                <div className="rounded-xl border border-slate-200/80 bg-[#F6F9FE] p-4">
                  <h3 className="text-sm font-semibold text-[#002D62]">
                    Reported Location
                  </h3>
                  <dl className="mt-3 space-y-3">
                    <div>
                      <dt className="text-xs font-semibold uppercase text-[#42547A]">
                        Location
                      </dt>
                      <dd className="mt-1 break-words text-sm font-medium text-slate-900">
                        {selectedSavedLocation
                          ? formatSavedLocation(selectedSavedLocation)
                          : selectedLocationLabel}
                      </dd>
                    </div>
                    {form.locationAddress.trim() ? (
                      <div>
                        <dt className="text-xs font-semibold uppercase text-[#42547A]">
                          Address
                        </dt>
                        <dd className="mt-1 break-words text-sm text-slate-700">
                          {form.locationAddress.trim()}
                        </dd>
                      </div>
                    ) : null}
                    {form.locationPlaceName.trim() ? (
                      <div>
                        <dt className="text-xs font-semibold uppercase text-[#42547A]">
                          Place
                        </dt>
                        <dd className="mt-1 break-words text-sm text-slate-700">
                          {form.locationPlaceName.trim()}
                        </dd>
                      </div>
                    ) : null}
                  </dl>
                </div>
              </div>

              {message ? (
                <div
                  className={`mt-4 rounded-xl border p-3 text-sm ${
                    message.type === "success"
                      ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                      : "border-[#DA291C]/20 bg-red-50 text-red-700"
                  }`}
                  aria-live="polite"
                >
                  <div className="flex gap-3">
                    {message.type === "success" ? (
                      <CheckCircle2
                        className="mt-0.5 h-5 w-5 shrink-0"
                        aria-hidden
                      />
                    ) : (
                      <AlertCircle
                        className="mt-0.5 h-5 w-5 shrink-0"
                        aria-hidden
                      />
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
                              View Report Status
                            </Button>
                          ) : null}
                          <Button
                            type="button"
                            variant="secondary"
                            size="sm"
                            onClick={() =>
                              router.push("/dashboard/citizen/reports")
                            }
                          >
                            My Reports
                          </Button>
                        </div>
                      ) : null}
                    </div>
                  </div>
                </div>
              ) : null}

              <div className="mt-6 flex flex-wrap gap-3 border-t border-slate-200/80 pt-4">
                <Button
                  type="button"
                  variant="secondary"
                  onClick={() => {
                    setStep("form");
                    setMessage(null);
                  }}
                  disabled={isSubmitting}
                >
                  Back
                </Button>
                <Button type="submit" isLoading={isSubmitting} disabled={!canSubmit}>
                  Submit Report
                </Button>
              </div>
            </CitizenSectionCard>
          </form>
        ) : (
          <form
            className="space-y-6"
            onSubmit={(event) => {
              event.preventDefault();
              handleContinueToReview();
            }}
          >
            <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,52fr)_minmax(0,48fr)]">
              <CitizenSectionCard
                title="Incident Details"
                icon={<ClipboardList className="h-5 w-5" aria-hidden />}
              >
                <div className="space-y-4">
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
                      rows={4}
                      placeholder="Add nearby landmarks, risks, affected people, or anything responders should know"
                      className="w-full rounded-xl border border-[#002D62]/20 bg-white px-4 py-3 text-sm text-gray-900 placeholder-gray-500 transition-colors focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                    />
                  </div>

                  <Input
                    type="datetime-local"
                    name="reportedAt"
                    label="Reported Time"
                    value={form.reportedAt}
                    onChange={handleChange}
                    icon={<CalendarClock className="h-4 w-4" aria-hidden />}
                    helpText="Defaults to the current time; adjust if needed."
                  />
                </div>
              </CitizenSectionCard>

              <CitizenSectionCard
                title="Reported Location"
                subtitle="Choose where this incident happened."
                icon={<MapPin className="h-5 w-5" aria-hidden />}
              >
                <div className="space-y-4">
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
                    searchPlaceholder="Search address, place, or landmark..."
                    mapClassName="h-[clamp(220px,32vh,280px)] w-full"
                    embeddedMapSectionClassName="mt-3 w-full shrink-0"
                    showSelectionSummary={false}
                  />

                  <div
                    className="rounded-lg border border-slate-200/80 bg-slate-50/80 px-3 py-2"
                    aria-live="polite"
                  >
                    {selectedCoordinates || form.savedLocationId ? (
                      <div className="space-y-1">
                        <p className="text-xs font-semibold text-slate-900">
                          Selected location
                        </p>
                        <p className="text-sm font-medium leading-snug text-slate-900">
                          {selectedLocationLabel}
                        </p>
                        {showDistinctPlaceName ? (
                          <p className="text-xs text-slate-500">
                            {selectedPlaceName}
                          </p>
                        ) : null}
                        <button
                          type="button"
                          onClick={clearMapLocation}
                          className="text-xs font-medium text-[#006747] underline-offset-2 transition hover:text-[#002D62] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#006747]/30"
                        >
                          Clear Location
                        </button>
                      </div>
                    ) : (
                      <div className="space-y-0.5">
                        <p className="text-xs font-semibold text-slate-900">
                          No location selected
                        </p>
                        <p className="text-xs leading-snug text-slate-600">
                          Search, choose a saved location, or select a map point.
                        </p>
                      </div>
                    )}
                  </div>

                  <div className="rounded-lg border border-slate-100 bg-slate-50/40 px-3 py-3">
                    <p className="text-xs font-medium text-slate-700">
                      Optional location details
                    </p>
                    <div className="mt-2 grid gap-2 sm:grid-cols-2">
                      <div>
                        <label
                          htmlFor="citizen-report-address"
                          className="block text-xs font-semibold text-slate-700"
                        >
                          Location Name or Address
                        </label>
                        <input
                          id="citizen-report-address"
                          name="locationAddress"
                          value={form.locationAddress}
                          onChange={handleChange}
                          placeholder="Building, road, or landmark description"
                          className="mt-1 w-full rounded-lg border border-[#002D62]/20 bg-white px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                        />
                      </div>
                      <div>
                        <label
                          htmlFor="citizen-report-place"
                          className="block text-xs font-semibold text-slate-700"
                        >
                          Place Name
                        </label>
                        <input
                          id="citizen-report-place"
                          name="locationPlaceName"
                          value={form.locationPlaceName}
                          onChange={handleChange}
                          placeholder="Optional landmark or place name"
                          className="mt-1 w-full rounded-lg border border-[#002D62]/20 bg-white px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35"
                        />
                      </div>
                    </div>
                  </div>
                </div>
              </CitizenSectionCard>
            </div>

            <div className="flex flex-wrap gap-3 border-t border-slate-200/80 pt-2">
              <Button
                type="button"
                variant="secondary"
                onClick={() => router.push("/dashboard/citizen")}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={!canSubmit}>
                Continue to Review
              </Button>
            </div>
          </form>
        )}
      </CitizenPageContent>
    </DashboardLayout>
  );
}
