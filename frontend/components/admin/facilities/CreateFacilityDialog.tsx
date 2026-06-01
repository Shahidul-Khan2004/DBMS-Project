"use client";

import dynamic from "next/dynamic";
import { type FormEvent, useCallback, useEffect, useState } from "react";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { getValidReportedCoordinates } from "@/components/dispatcher/triage/reportedLocationCoords";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import type {
  LocationPickerSelectionDetails,
  LocationPickerValue,
} from "@/components/location/LocationPicker";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { ApiError, getApiErrorMessage } from "@/lib/api";
import { createAdminFacility } from "@/lib/admin-facility-api";
import { FACILITY_TYPE_OPTIONS } from "@/lib/admin-facility-format";
import { buildCreateFacilityPayload } from "@/lib/build-create-facility-payload";
import type { AdminFacility } from "@/types/admin-facility";
import { toast } from "sonner";

const MAP_WRAPPER_CLASS = "h-[240px] w-full shrink-0";

const LocationPicker = dynamic(
  () =>
    import("@/components/location/LocationPicker").then((mod) => ({
      default: mod.LocationPicker,
    })),
  {
    ssr: false,
    loading: () => (
      <div
        className={`${MAP_WRAPPER_CLASS} animate-pulse rounded-2xl bg-slate-100`}
      />
    ),
  },
);

type CreateFacilityDialogProps = {
  open: boolean;
  onClose: () => void;
  onSuccess: (facility: AdminFacility) => void;
};

export function CreateFacilityDialog({
  open,
  onClose,
  onSuccess,
}: CreateFacilityDialogProps) {
  const [facilityCode, setFacilityCode] = useState("");
  const [name, setName] = useState("");
  const [facilityTypeCode, setFacilityTypeCode] = useState<string>(
    FACILITY_TYPE_OPTIONS[0].value,
  );
  const [pickerValue, setPickerValue] = useState<LocationPickerValue | null>(
    null,
  );
  const [addressText, setAddressText] = useState("");
  const [adminAreaLabel, setAdminAreaLabel] = useState("");
  const [adminAreaId, setAdminAreaId] = useState<number | null>(null);
  const [placeName, setPlaceName] = useState("");
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open) return;
    setFacilityCode("");
    setName("");
    setFacilityTypeCode(FACILITY_TYPE_OPTIONS[0].value);
    setPickerValue(null);
    setAddressText("");
    setAdminAreaLabel("");
    setAdminAreaId(null);
    setPlaceName("");
    setFieldErrors({});
    setSubmitError(null);
  }, [open]);

  useEffect(() => {
    if (!open) return;

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !isSubmitting) onClose();
    };

    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [open, isSubmitting, onClose]);

  const clearLocationFields = useCallback(() => {
    setAddressText("");
    setAdminAreaLabel("");
    setAdminAreaId(null);
    setPlaceName("");
  }, []);

  const handlePickerChange = useCallback(
    (
      location: LocationPickerValue,
      details?: LocationPickerSelectionDetails,
    ) => {
      setPickerValue(location);

      const isInterimClear =
        details != null &&
        details.addressText === "" &&
        !details.placeName &&
        !details.adminAreaLabel &&
        details.adminAreaId == null;

      if (!details || isInterimClear) {
        setAddressText("");
        setAdminAreaLabel("");
        setAdminAreaId(null);
        return;
      }

      const resolvedAddress =
        details.addressText?.trim() || details.placeName?.trim() || "";
      if (resolvedAddress) {
        setAddressText(resolvedAddress);
      }

      if (details.adminAreaLabel?.trim()) {
        setAdminAreaLabel(details.adminAreaLabel);
      } else {
        setAdminAreaLabel("");
      }
      setAdminAreaId(details.adminAreaId ?? null);
    },
    [],
  );

  const handleClearLocation = useCallback(() => {
    setPickerValue(null);
    clearLocationFields();
  }, [clearLocationFields]);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const errors: Record<string, string> = {};

    if (!facilityCode.trim()) errors.facilityCode = "Facility code is required.";
    if (!name.trim()) errors.name = "Name is required.";
    if (!facilityTypeCode.trim()) {
      errors.facilityTypeCode = "Facility type is required.";
    }
    if (!getValidReportedCoordinates(pickerValue?.latitude, pickerValue?.longitude)) {
      errors.location = "Select a location on the map.";
    }

    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }

    const payload = buildCreateFacilityPayload({
      facilityCode,
      name,
      facilityTypeCode,
      addressText,
      placeName,
      adminAreaId,
      selectedLocation: pickerValue,
    });

    if (!payload) {
      setFieldErrors({ location: "Select a location on the map." });
      return;
    }

    setFieldErrors({});
    setSubmitError(null);
    setIsSubmitting(true);

    try {
      const response = await createAdminFacility(payload);
      toast.success("Facility created.");
      onClose();
      onSuccess(response.facility);
    } catch (err) {
      setSubmitError(
        err instanceof ApiError
          ? getApiErrorMessage(err, err.message)
          : err instanceof Error
            ? err.message
            : "Failed to create facility.",
      );
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!open) return null;

  const validCoords = getValidReportedCoordinates(
    pickerValue?.latitude,
    pickerValue?.longitude,
  );

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/40 p-4">
      <form
        className="flex max-h-[calc(100vh-72px)] w-full max-w-[min(1080px,calc(100vw-2rem))] flex-col overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-labelledby="create-facility-title"
        aria-modal="true"
        onSubmit={(event) => void handleSubmit(event)}
      >
        <div className="shrink-0 border-b border-slate-100 px-5 py-3.5">
          <h2
            id="create-facility-title"
            className="text-lg font-semibold text-slate-900"
          >
            Add facility
          </h2>
          <p className="mt-0.5 text-sm text-slate-600">
            Register a shelter, hospital, relief hub, or other support facility.
          </p>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-3.5 lg:overflow-hidden">
          {submitError ? (
            <div className="mb-3">
              <ErrorAlert message={submitError} />
            </div>
          ) : null}

          <div className="grid min-h-0 grid-cols-1 gap-4 lg:grid-cols-[minmax(0,44%)_minmax(0,56%)] lg:items-start">
            <div className="space-y-2.5">
              <div>
                <FieldLabel htmlFor="facility-code" required>
                  Facility code
                </FieldLabel>
                <input
                  id="facility-code"
                  type="text"
                  value={facilityCode}
                  onChange={(e) => setFacilityCode(e.target.value)}
                  className={triageFieldClassName}
                  disabled={isSubmitting}
                />
                {fieldErrors.facilityCode ? (
                  <p className="mt-0.5 text-xs text-red-600">
                    {fieldErrors.facilityCode}
                  </p>
                ) : null}
              </div>
              <div>
                <FieldLabel htmlFor="facility-name" required>
                  Name
                </FieldLabel>
                <input
                  id="facility-name"
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className={triageFieldClassName}
                  disabled={isSubmitting}
                />
                {fieldErrors.name ? (
                  <p className="mt-0.5 text-xs text-red-600">{fieldErrors.name}</p>
                ) : null}
              </div>
              <div>
                <FieldLabel htmlFor="facility-type" required>
                  Facility type
                </FieldLabel>
                <select
                  id="facility-type"
                  value={facilityTypeCode}
                  onChange={(e) => setFacilityTypeCode(e.target.value)}
                  className={triageFieldClassName}
                  disabled={isSubmitting}
                >
                  {FACILITY_TYPE_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
                {fieldErrors.facilityTypeCode ? (
                  <p className="mt-0.5 text-xs text-red-600">
                    {fieldErrors.facilityTypeCode}
                  </p>
                ) : null}
              </div>
            </div>

            <div className="flex min-h-0 flex-col">
              <FieldLabel required>Location</FieldLabel>
              <p className="mt-0.5 text-xs text-slate-600">
                Search or pick a point on the map. Address and administrative area
                are resolved from the selection.
              </p>
              <div className="mt-2 min-w-0">
                <LocationPicker
                  value={pickerValue}
                  onChange={handlePickerChange}
                  showCurrentLocation={false}
                  scrollWheelZoom={false}
                  embedded
                  embeddedCompact
                  searchPlaceholder="Search address, place, or landmark..."
                  mapWrapperClassName={MAP_WRAPPER_CLASS}
                  mapClassName="h-full w-full"
                  embeddedMapSectionClassName="mt-1.5 w-full shrink-0"
                  className="w-full shrink-0"
                  disabled={isSubmitting}
                />
              </div>

              {validCoords ? (
                <div className="relative z-10 mt-2.5 space-y-2">
                  <div>
                    <span className="text-xs font-medium text-slate-500">
                      Address
                    </span>
                    <p className="mt-0.5 text-sm text-slate-900">
                      {addressText.trim() || "—"}
                    </p>
                  </div>
                  <div>
                    <span className="text-xs font-medium text-slate-500">
                      Administrative area
                    </span>
                    <p className="mt-0.5 text-sm text-slate-900">
                      {adminAreaLabel.trim() || "—"}
                    </p>
                  </div>
                  <div>
                    <FieldLabel htmlFor="facility-place-name">
                      Place name
                    </FieldLabel>
                    <input
                      id="facility-place-name"
                      type="text"
                      value={placeName}
                      onChange={(e) => setPlaceName(e.target.value)}
                      className={triageFieldClassName}
                      placeholder="e.g. Kurigram College main gate"
                      autoComplete="off"
                      disabled={isSubmitting}
                    />
                  </div>
                  <button
                    type="button"
                    onClick={handleClearLocation}
                    disabled={isSubmitting}
                    className="cursor-pointer text-xs font-medium text-[#006747] underline-offset-2 transition hover:text-[#002D62] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#006747]/30 focus-visible:ring-offset-1 disabled:cursor-not-allowed disabled:text-slate-400 disabled:hover:text-slate-400 disabled:hover:no-underline"
                  >
                    Clear location
                  </button>
                </div>
              ) : null}

              {fieldErrors.location ? (
                <p className="mt-0.5 text-xs text-red-600">{fieldErrors.location}</p>
              ) : null}
            </div>
          </div>
        </div>

        <div className="flex shrink-0 justify-end gap-2 border-t border-slate-100 px-5 py-3.5">
          <Button
            type="button"
            variant="secondary"
            onClick={onClose}
            disabled={isSubmitting}
          >
            Cancel
          </Button>
          <Button type="submit" isLoading={isSubmitting}>
            Create facility
          </Button>
        </div>
      </form>
    </div>
  );
}
