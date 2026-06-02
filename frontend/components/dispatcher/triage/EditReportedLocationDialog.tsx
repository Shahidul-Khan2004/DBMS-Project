"use client";

import dynamic from "next/dynamic";
import {
  type FormEvent,
  useCallback,
  useEffect,
  useState,
} from "react";
import { toast } from "sonner";
import type {
  LocationPickerSelectionDetails,
  LocationPickerValue,
} from "@/components/location/LocationPicker";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import {
  triageFieldClassName,
} from "@/components/dispatcher/triage/triageFormStyles";
import type { IntakeQueueItem } from "@/components/dispatcher/triage/types";
import {
  formatReportedCoordinates,
  getValidReportedCoordinates,
} from "@/components/dispatcher/triage/reportedLocationCoords";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import {
  mapApiErrorToRouteMessage,
  updateIntakeReportedLocation,
} from "@/lib/operations-intake-triage";

const LocationPicker = dynamic(
  () =>
    import("@/components/location/LocationPicker").then((mod) => ({
      default: mod.LocationPicker,
    })),
  {
    ssr: false,
    loading: () => (
      <div className="h-[280px] w-full animate-pulse rounded-2xl bg-slate-100" />
    ),
  },
);

interface EditReportedLocationDialogProps {
  open: boolean;
  item: IntakeQueueItem | null;
  onClose: () => void;
  onSuccess: () => void;
  dialogTitle?: string;
  currentLocationLabel?: string;
  successMessage?: string;
}

function getInitialPickerValue(
  item: IntakeQueueItem,
): LocationPickerValue | null {
  return getValidReportedCoordinates(
    item.location.latitude,
    item.location.longitude,
  );
}

export function EditReportedLocationDialog({
  open,
  item,
  onClose,
  onSuccess,
  dialogTitle = "Edit Reported Location",
  currentLocationLabel = "Current reported location:",
  successMessage = "Reported location updated.",
}: EditReportedLocationDialogProps) {
  const [pickerValue, setPickerValue] = useState<LocationPickerValue | null>(
    null,
  );
  const [addressText, setAddressText] = useState("");
  const [placeName, setPlaceName] = useState("");
  const [showManualCoords, setShowManualCoords] = useState(false);
  const [manualLatitude, setManualLatitude] = useState("");
  const [manualLongitude, setManualLongitude] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  useEffect(() => {
    if (!open || !item) return;

    const initialCoords = getInitialPickerValue(item);
    setPickerValue(initialCoords);
    setAddressText(item.location.addressText ?? "");
    setPlaceName(item.location.areaName ?? "");
    setShowManualCoords(false);
    setManualLatitude(
      initialCoords != null ? String(initialCoords.latitude) : "",
    );
    setManualLongitude(
      initialCoords != null ? String(initialCoords.longitude) : "",
    );
    setError(null);
  }, [open, item]);

  useEffect(() => {
    if (!open) return;

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !isSubmitting) {
        onClose();
      }
    };

    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [open, isSubmitting, onClose]);

  const handlePickerChange = useCallback(
    (
      location: LocationPickerValue,
      details?: LocationPickerSelectionDetails,
    ) => {
      setPickerValue(location);
      setManualLatitude(String(location.latitude));
      setManualLongitude(String(location.longitude));
      setError(null);

      if (details?.addressText != null && details.addressText !== "") {
        setAddressText(details.addressText);
      }
      if (details?.placeName != null && details.placeName !== "") {
        setPlaceName(details.placeName);
      }
    },
    [],
  );

  const applyManualCoordinates = useCallback(() => {
    const parsedLatitude = Number(manualLatitude);
    const parsedLongitude = Number(manualLongitude);
    const coords = getValidReportedCoordinates(
      parsedLatitude,
      parsedLongitude,
    );

    if (!coords) {
      setError("Enter valid latitude (-90 to 90) and longitude (-180 to 180).");
      return;
    }

    setPickerValue(coords);
    setError(null);
  }, [manualLatitude, manualLongitude]);

  if (!open || !item) return null;

  const reportPublicUuid = item.id;
  const validCoords = getValidReportedCoordinates(
    pickerValue?.latitude,
    pickerValue?.longitude,
  );
  const canSave = validCoords != null && !isSubmitting;

  const selectedLocationLabel =
    addressText.trim() ||
    placeName.trim() ||
    "Map location selected";

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    if (!validCoords) {
      setError("Search or select a corrected location on the map before saving.");
      return;
    }

    setIsSubmitting(true);
    try {
      await updateIntakeReportedLocation(reportPublicUuid, {
        location: {
          latitude: validCoords.latitude,
          longitude: validCoords.longitude,
          address_text: addressText.trim() || undefined,
          place_name: placeName.trim() || undefined,
          source: "dispatcher_selected",
        },
      });
      toast.success(successMessage);
      onSuccess();
      onClose();
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Failed to update reported location", err);
      }
      setError(mapApiErrorToRouteMessage(err, "location"));
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div
        className="relative z-[60] flex max-h-[90vh] w-full max-w-3xl flex-col overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-labelledby="edit-location-title"
        aria-modal="true"
      >
        <div className="shrink-0 border-b border-slate-100 px-5 py-4">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <h2
                id="edit-location-title"
                className="text-base font-semibold text-slate-900"
              >
                {dialogTitle}
              </h2>
              <p className="mt-1 text-sm text-slate-600">{item.summary}</p>
              <p className="mt-2 text-sm text-slate-700">
                <span className="font-medium text-slate-800">
                  {currentLocationLabel}
                </span>{" "}
                {item.location.addressText || "Location unavailable"}
              </p>
            </div>
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={onClose}
              disabled={isSubmitting}
              aria-label="Close"
            >
              Close
            </Button>
          </div>
        </div>

        <form
          className="flex min-h-0 flex-1 flex-col"
          onSubmit={(event) => void handleSubmit(event)}
        >
          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
            <FieldLabel required className="mb-2 block">
              Corrected Location
            </FieldLabel>
            <div className="min-w-0">
              <LocationPicker
                value={pickerValue}
                onChange={handlePickerChange}
                selectedAddress={addressText}
                selectedPlaceName={placeName}
                syncSearchQueryToSelectedLabel={false}
                showCurrentLocation={false}
                showSelectionSummary={false}
                scrollWheelZoom={false}
                sectionTitle="Search for corrected location"
                sectionDescription="Search or click the map to place the corrected reported location."
                searchPlaceholder="Search an address, place or landmark..."
              />
            </div>

            {validCoords ? (
              <div
                className="mt-4 rounded-xl border border-slate-200 bg-slate-50 px-4 py-3"
                aria-live="polite"
              >
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Selected Corrected Location
                </p>
                <p className="mt-1 text-sm font-medium text-slate-900">
                  {selectedLocationLabel}
                </p>
                <p className="mt-1 text-xs text-slate-600">
                  Coordinates:{" "}
                  {formatReportedCoordinates(
                    validCoords.latitude,
                    validCoords.longitude,
                  )}
                </p>
              </div>
            ) : (
              <p
                className="mt-4 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900"
                aria-live="polite"
              >
                Search for a place or click the map to select the corrected
                reported location.
              </p>
            )}

            <div className="mt-4 space-y-3">
              <div>
                <FieldLabel htmlFor="edit-address">Address Details</FieldLabel>
                <input
                  id="edit-address"
                  type="text"
                  value={addressText}
                  onChange={(event) => setAddressText(event.target.value)}
                  className={triageFieldClassName}
                  placeholder="Building, road, or landmark description"
                />
              </div>
              <div>
                <FieldLabel htmlFor="edit-place">Place Name</FieldLabel>
                <input
                  id="edit-place"
                  type="text"
                  value={placeName}
                  onChange={(event) => setPlaceName(event.target.value)}
                  className={triageFieldClassName}
                  placeholder="Optional landmark or place name"
                />
              </div>
            </div>

            <div className="mt-4">
              <button
                type="button"
                className="text-sm font-medium text-[#002D62] underline-offset-2 hover:underline"
                onClick={() => setShowManualCoords((current) => !current)}
                aria-expanded={showManualCoords}
              >
                {showManualCoords
                  ? "Hide manual coordinates"
                  : "Enter coordinates manually"}
              </button>

              {showManualCoords ? (
                <div className="mt-3 space-y-3 rounded-xl border border-slate-200 bg-white p-3">
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div>
                      <FieldLabel htmlFor="edit-manual-lat">Latitude</FieldLabel>
                      <input
                        id="edit-manual-lat"
                        type="number"
                        step="any"
                        value={manualLatitude}
                        onChange={(event) =>
                          setManualLatitude(event.target.value)
                        }
                        className={triageFieldClassName}
                      />
                    </div>
                    <div>
                      <FieldLabel htmlFor="edit-manual-lng">Longitude</FieldLabel>
                      <input
                        id="edit-manual-lng"
                        type="number"
                        step="any"
                        value={manualLongitude}
                        onChange={(event) =>
                          setManualLongitude(event.target.value)
                        }
                        className={triageFieldClassName}
                      />
                    </div>
                  </div>
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    onClick={applyManualCoordinates}
                  >
                    Apply coordinates
                  </Button>
                </div>
              ) : null}
            </div>

            {error ? (
              <div className="mt-4">
                <ErrorAlert message={error} />
              </div>
            ) : null}
          </div>

          <div className="flex shrink-0 justify-end gap-2 border-t border-slate-100 px-5 py-4">
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={onClose}
              disabled={isSubmitting}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              size="sm"
              isLoading={isSubmitting}
              disabled={!canSave}
            >
              Save Location
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
