"use client";

import dynamic from "next/dynamic";
import {
  type FormEvent,
  useCallback,
  useEffect,
  useState,
} from "react";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import {
  formatReportedCoordinates,
  getValidReportedCoordinates,
} from "@/components/dispatcher/triage/reportedLocationCoords";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import type {
  LocationPickerSelectionDetails,
  LocationPickerValue,
} from "@/components/location/LocationPicker";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError } from "@/lib/api";
import { onboardAgency } from "@/lib/admin-agency-api";
import {
  buildOnboardAgencyPayload,
  getSelectedLocationCoordinates,
} from "@/lib/build-onboard-agency-payload";
import {
  formatAdminAgencyError,
  formatOnboardAgencyValidationDetail,
  ONBOARD_AGENCY_VALIDATION_MESSAGE,
} from "@/lib/admin-agency-errors";
import { ADMIN_AGENCY_ONBOARD_TYPE_OPTIONS } from "@/lib/admin-agency-types";
import type { AdminAgencyListItem } from "@/types/admin-agency";
import { toast } from "sonner";

const ONBOARD_MAP_WRAPPER_CLASS = "h-[240px] w-full shrink-0";

const LocationPicker = dynamic(
  () =>
    import("@/components/location/LocationPicker").then((mod) => ({
      default: mod.LocationPicker,
    })),
  {
    ssr: false,
    loading: () => (
      <div
        className={`${ONBOARD_MAP_WRAPPER_CLASS} animate-pulse rounded-2xl bg-slate-100`}
      />
    ),
  },
);

export type OnboardAgencySuccessResult = {
  agency: AdminAgencyListItem;
  agencyTypeCode: string;
  openLinkRepresentative: boolean;
};

type OnboardSubmitError =
  | { kind: "validation"; detail: string }
  | { kind: "generic"; message: string };

type OnboardAgencyDialogProps = {
  open: boolean;
  onClose: () => void;
  onSuccess: (result: OnboardAgencySuccessResult) => void;
};

export function OnboardAgencyDialog({
  open,
  onClose,
  onSuccess,
}: OnboardAgencyDialogProps) {
  const [agencyCode, setAgencyCode] = useState("");
  const [agencyName, setAgencyName] = useState("");
  const [agencyTypeCode, setAgencyTypeCode] = useState<string>(
    ADMIN_AGENCY_ONBOARD_TYPE_OPTIONS[0].value,
  );
  const [description, setDescription] = useState("");
  const [pickerValue, setPickerValue] = useState<LocationPickerValue | null>(
    null,
  );
  const [addressText, setAddressText] = useState("");
  const [placeName, setPlaceName] = useState("");
  const [linkRepresentativeAfterCreate, setLinkRepresentativeAfterCreate] =
    useState(false);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [submitError, setSubmitError] = useState<OnboardSubmitError | null>(
    null,
  );
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setAgencyCode("");
    setAgencyName("");
    setAgencyTypeCode(ADMIN_AGENCY_ONBOARD_TYPE_OPTIONS[0].value);
    setDescription("");
    setPickerValue(null);
    setAddressText("");
    setPlaceName("");
    setLinkRepresentativeAfterCreate(false);
    setFieldErrors({});
    setSubmitError(null);
  }, [open]);

  useEffect(() => {
    if (!open) return;

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !isSubmitting) {
        onClose();
      }
    };

    window.addEventListener("keydown", onKeyDown);

    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [open, isSubmitting, onClose]);

  const handleClose = () => {
    if (isSubmitting) return;
    onClose();
  };

  const handlePickerChange = useCallback(
    (
      location: LocationPickerValue,
      details?: LocationPickerSelectionDetails,
    ) => {
      setPickerValue(location);
      if (details?.addressText != null && details.addressText !== "") {
        setAddressText(details.addressText);
      }
      if (details?.placeName != null && details.placeName !== "") {
        setPlaceName(details.placeName);
      }
    },
    [],
  );

  const handleClearLocation = useCallback(() => {
    setPickerValue(null);
    setAddressText("");
    setPlaceName("");
  }, []);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const errors: Record<string, string> = {};

    if (!agencyCode.trim()) errors.agencyCode = "Agency code is required.";
    if (!agencyName.trim()) errors.agencyName = "Agency name is required.";
    if (!agencyTypeCode.trim()) {
      errors.agencyTypeCode = "Agency type is required.";
    }

    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }

    setFieldErrors({});
    setSubmitError(null);
    setIsSubmitting(true);

    const payload = buildOnboardAgencyPayload({
      agencyCode,
      agencyName,
      agencyTypeCode,
      description,
      addressText,
      placeName,
      selectedLocation: pickerValue,
    });

    if (process.env.NODE_ENV === "development") {
      console.log(
        "Admin onboard agency payload",
        JSON.stringify(payload, null, 2),
      );
      if (pickerValue && !getSelectedLocationCoordinates(pickerValue)) {
        console.warn(
          "Onboard agency: map selection present but coordinates could not be extracted; omitting head_office_location",
        );
      }
    }

    try {
      const response = await onboardAgency(payload);
      toast.success("Agency onboarded.");
      onClose();
      onSuccess({
        agency: response.agency,
        agencyTypeCode,
        openLinkRepresentative: linkRepresentativeAfterCreate,
      });
    } catch (err) {
      if (
        process.env.NODE_ENV === "development" &&
        err instanceof ApiError &&
        err.code === "VALIDATION_ERROR"
      ) {
        console.error("Onboard agency validation details", err.details);
      }

      if (err instanceof ApiError && err.code === "VALIDATION_ERROR") {
        setSubmitError({
          kind: "validation",
          detail: formatOnboardAgencyValidationDetail(err),
        });
      } else {
        setSubmitError({
          kind: "generic",
          message: formatAdminAgencyError(err),
        });
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!open) return null;

  const validCoords = getValidReportedCoordinates(
    pickerValue?.latitude,
    pickerValue?.longitude,
  );

  const hasAddressWithoutCoords =
    !validCoords && (addressText.trim() !== "" || placeName.trim() !== "");

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/40 p-4">
      <form
        className="flex max-h-[calc(100vh-72px)] w-full max-w-[min(1080px,calc(100vw-2rem))] flex-col overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-labelledby="onboard-agency-title"
        aria-modal="true"
        onSubmit={(event) => void handleSubmit(event)}
      >
        <div className="shrink-0 border-b border-slate-100 px-5 py-3.5">
          <h2
            id="onboard-agency-title"
            className="text-lg font-semibold text-slate-900"
          >
            Onboard agency
          </h2>
          <p className="mt-0.5 text-sm text-slate-600">
            Create a new agency and optionally set its head office location.
          </p>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-3.5 lg:overflow-hidden">
          {submitError?.kind === "validation" ? (
            <div
              className="mb-3 rounded-lg border border-[#DA291C]/25 bg-red-50 px-3 py-2.5 text-red-800"
              role="alert"
            >
              <p className="text-sm font-medium">
                {ONBOARD_AGENCY_VALIDATION_MESSAGE}
              </p>
              {submitError.detail ? (
                <p className="mt-1 text-xs text-slate-600">
                  {submitError.detail}
                </p>
              ) : null}
            </div>
          ) : submitError?.kind === "generic" ? (
            <div className="mb-3">
              <ErrorAlert message={submitError.message} />
            </div>
          ) : null}

          <div className="grid min-h-0 grid-cols-1 gap-4 lg:grid-cols-[minmax(0,44%)_minmax(0,56%)] lg:items-start">
            <div className="space-y-2.5">
              <section
                className="space-y-2.5"
                aria-labelledby="onboard-agency-details"
              >
                <h3
                  id="onboard-agency-details"
                  className="text-sm font-semibold text-slate-900"
                >
                  Agency details
                </h3>
                <div>
                  <FieldLabel htmlFor="onboard-agency-code" required>
                    Agency code
                  </FieldLabel>
                  <input
                    id="onboard-agency-code"
                    type="text"
                    value={agencyCode}
                    onChange={(e) => setAgencyCode(e.target.value)}
                    className={triageFieldClassName}
                    autoComplete="off"
                    disabled={isSubmitting}
                  />
                  {fieldErrors.agencyCode ? (
                    <p className="mt-0.5 text-xs text-red-600">
                      {fieldErrors.agencyCode}
                    </p>
                  ) : null}
                </div>
                <div>
                  <FieldLabel htmlFor="onboard-agency-name" required>
                    Agency name
                  </FieldLabel>
                  <input
                    id="onboard-agency-name"
                    type="text"
                    value={agencyName}
                    onChange={(e) => setAgencyName(e.target.value)}
                    className={triageFieldClassName}
                    disabled={isSubmitting}
                  />
                  {fieldErrors.agencyName ? (
                    <p className="mt-0.5 text-xs text-red-600">
                      {fieldErrors.agencyName}
                    </p>
                  ) : null}
                </div>
                <div>
                  <FieldLabel htmlFor="onboard-agency-type" required>
                    Agency type
                  </FieldLabel>
                  <select
                    id="onboard-agency-type"
                    value={agencyTypeCode}
                    onChange={(e) => setAgencyTypeCode(e.target.value)}
                    className={triageFieldClassName}
                    disabled={isSubmitting}
                  >
                    {ADMIN_AGENCY_ONBOARD_TYPE_OPTIONS.map((opt) => (
                      <option key={opt.value} value={opt.value}>
                        {opt.label}
                      </option>
                    ))}
                  </select>
                  {fieldErrors.agencyTypeCode ? (
                    <p className="mt-0.5 text-xs text-red-600">
                      {fieldErrors.agencyTypeCode}
                    </p>
                  ) : null}
                </div>
                <div>
                  <FieldLabel htmlFor="onboard-description">
                    Description
                  </FieldLabel>
                  <textarea
                    id="onboard-description"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    className={`${triageFieldClassName} min-h-[72px] resize-y`}
                    rows={2}
                    disabled={isSubmitting}
                  />
                </div>
              </section>

              <div className="border-t border-slate-100 pt-2.5">
                <label className="flex items-start gap-2 text-sm text-slate-700">
                  <input
                    type="checkbox"
                    className="mt-0.5"
                    checked={linkRepresentativeAfterCreate}
                    onChange={(e) =>
                      setLinkRepresentativeAfterCreate(e.target.checked)
                    }
                    disabled={isSubmitting}
                  />
                  Link a representative after creating this agency
                </label>
                <p className="mt-1 pl-5 text-xs text-slate-500">
                  Representative access can be linked after the agency is
                  created.
                </p>
              </div>
            </div>

            <section
              className="flex min-h-0 min-w-0 flex-col"
              aria-labelledby="onboard-head-office"
            >
              <h3
                id="onboard-head-office"
                className="text-sm font-semibold text-slate-900"
              >
                Head office location
              </h3>
              <p className="mt-0.5 text-xs text-slate-600">
                Search the map or enter a readable address. This is optional.
              </p>

              <div className="mt-2 min-w-0">
                <LocationPicker
                  value={pickerValue}
                  onChange={handlePickerChange}
                  selectedAddress={addressText}
                  selectedPlaceName={placeName}
                  syncSearchQueryToSelectedLabel={false}
                  showCurrentLocation={false}
                  showSelectionSummary={false}
                  scrollWheelZoom={false}
                  embedded
                  embeddedCompact
                  disabled={isSubmitting}
                  searchPlaceholder="Search address, place, or landmark..."
                  mapWrapperClassName={ONBOARD_MAP_WRAPPER_CLASS}
                  mapClassName="h-full w-full"
                  embeddedMapSectionClassName="mt-1.5 w-full shrink-0"
                  className="w-full shrink-0"
                />
              </div>

              <div className="mt-2.5 space-y-2">
                <div>
                  <FieldLabel htmlFor="onboard-address-text">
                    Address text
                  </FieldLabel>
                  <input
                    id="onboard-address-text"
                    type="text"
                    value={addressText}
                    onChange={(e) => setAddressText(e.target.value)}
                    className={triageFieldClassName}
                    autoComplete="off"
                    disabled={isSubmitting}
                  />
                </div>
                <div>
                  <FieldLabel htmlFor="onboard-place-name">
                    Place name
                  </FieldLabel>
                  <input
                    id="onboard-place-name"
                    type="text"
                    value={placeName}
                    onChange={(e) => setPlaceName(e.target.value)}
                    className={triageFieldClassName}
                    autoComplete="off"
                    disabled={isSubmitting}
                  />
                </div>

                {validCoords ? (
                  <div className="space-y-1" aria-live="polite">
                    <p className="text-xs text-slate-500">
                      {formatReportedCoordinates(
                        validCoords.latitude,
                        validCoords.longitude,
                      )}
                    </p>
                    <button
                      type="button"
                      onClick={handleClearLocation}
                      disabled={isSubmitting}
                      className="cursor-pointer text-xs font-medium text-[#006747] underline-offset-2 transition hover:text-[#002D62] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#006747]/30 focus-visible:ring-offset-1 disabled:cursor-not-allowed disabled:text-slate-400 disabled:hover:text-slate-400 disabled:hover:no-underline"
                    >
                      Clear location
                    </button>
                  </div>
                ) : hasAddressWithoutCoords ? (
                  <p className="text-xs text-slate-500">
                    Select a map point to store coordinates. Address text alone
                    will not create a head office location.
                  </p>
                ) : null}
              </div>
            </section>
          </div>
        </div>

        <div className="flex shrink-0 justify-end gap-2 border-t border-slate-100 px-5 py-3.5">
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={handleClose}
            disabled={isSubmitting}
          >
            Cancel
          </Button>
          <Button type="submit" size="sm" isLoading={isSubmitting}>
            Create agency
          </Button>
        </div>
      </form>
    </div>
  );
}
