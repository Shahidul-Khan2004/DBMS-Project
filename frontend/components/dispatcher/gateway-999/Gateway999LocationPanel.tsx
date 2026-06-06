"use client";

import { useCallback } from "react";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import type { SelectedIncidentLocation } from "@/components/dispatcher/incidents/create/types";
import { getValidReportedCoordinates } from "@/components/dispatcher/triage/reportedLocationCoords";
import type {
  LocationPickerSelectionDetails,
  LocationPickerValue,
} from "@/components/location/LocationPicker";
import dynamic from "next/dynamic";

const MAP_WRAPPER_CLASS =
  "mx-auto h-[210px] w-full max-w-[760px] min-w-0 shrink-0 xl:h-[230px]";

const MAP_CONTAINER_CLASS = "h-full w-full";

const compactLabelClassName = "block text-xs font-semibold text-slate-700";

const compactFieldClassName =
  "mt-0.5 w-full rounded-lg border border-[#002D62]/20 bg-white px-2.5 py-1.5 text-sm text-slate-900 placeholder:text-slate-400 focus:border-[#006747] focus:outline-none focus:ring-2 focus:ring-[#006747]/35 disabled:cursor-not-allowed disabled:bg-slate-50 disabled:text-slate-500";

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

type Gateway999LocationPanelProps = {
  selectedLocation: SelectedIncidentLocation | null;
  addressText: string;
  placeName: string;
  isSubmitting: boolean;
  showValidation: boolean;
  onLocationChange: (location: SelectedIncidentLocation | null) => void;
  onAddressTextChange: (value: string) => void;
  onPlaceNameChange: (value: string) => void;
};

function ClearLocationButton({
  onClick,
  disabled,
}: {
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="cursor-pointer text-xs font-medium text-[#006747] underline-offset-2 transition hover:text-[#002D62] hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#006747]/30 focus-visible:ring-offset-1 disabled:cursor-not-allowed disabled:text-slate-400 disabled:hover:text-slate-400 disabled:hover:no-underline"
    >
      Clear Location
    </button>
  );
}

export function Gateway999LocationPanel({
  selectedLocation,
  addressText,
  placeName,
  isSubmitting,
  showValidation,
  onLocationChange,
  onAddressTextChange,
  onPlaceNameChange,
}: Gateway999LocationPanelProps) {
  const validCoords = selectedLocation
    ? getValidReportedCoordinates(
        selectedLocation.latitude,
        selectedLocation.longitude,
      )
    : null;

  const locationError =
    showValidation && !validCoords
      ? "Select a reported location before submitting."
      : null;

  const pickerAddressText = selectedLocation?.addressText?.trim() ?? "";
  const pickerPlaceName = selectedLocation?.placeName?.trim() ?? "";

  const locationDisplayLabel =
    pickerAddressText || pickerPlaceName || null;

  const pickerValue: LocationPickerValue | null = validCoords;

  const handlePickerChange = useCallback(
    (
      location: LocationPickerValue,
      details?: LocationPickerSelectionDetails,
    ) => {
      onLocationChange({
        latitude: location.latitude,
        longitude: location.longitude,
        addressText: details?.addressText?.trim() || undefined,
        placeName: details?.placeName?.trim() || undefined,
      });
    },
    [onLocationChange],
  );

  const handleClearLocation = useCallback(() => {
    onLocationChange(null);
    onAddressTextChange("");
    onPlaceNameChange("");
  }, [onLocationChange, onAddressTextChange, onPlaceNameChange]);

  const showDistinctPlaceName =
    pickerPlaceName &&
    pickerPlaceName !== pickerAddressText &&
    pickerPlaceName !== locationDisplayLabel;

  return (
    <CommandSectionCard
      title="Reported Location"
      titleRequired
      subtitle="Search or place a marker for where this call was reported."
      className="h-full !p-4 sm:!p-4"
      bodyClassName="!mt-2"
      fillHeight
      scrollableBody
    >
      <div className="flex flex-col gap-2.5">
        <LocationPicker
          value={pickerValue}
          onChange={handlePickerChange}
          selectedAddress={selectedLocation?.addressText}
          selectedPlaceName={selectedLocation?.placeName}
          syncSearchQueryToSelectedLabel={false}
          showCurrentLocation={false}
          showSelectionSummary={false}
          scrollWheelZoom={false}
          embedded
          embeddedCompact
          disabled={isSubmitting}
          searchPlaceholder="Search address, place, or landmark..."
          mapClassName={MAP_CONTAINER_CLASS}
          mapWrapperClassName={MAP_WRAPPER_CLASS}
          embeddedMapSectionClassName="mt-3 w-full shrink-0"
          className="w-full shrink-0"
        />

        <div
          className="shrink-0 rounded-lg border border-slate-200/80 bg-slate-50/80 px-2.5 py-1"
          aria-live="polite"
        >
          {validCoords ? (
            <div className="space-y-0.5">
              <div className="flex items-center justify-between gap-2">
                <p className="text-xs font-semibold text-slate-900">
                  Selected location
                </p>
                <ClearLocationButton
                  onClick={handleClearLocation}
                  disabled={isSubmitting}
                />
              </div>
              <p className="text-sm font-medium leading-snug text-slate-900">
                {locationDisplayLabel ?? "Selected map point"}
              </p>
              {showDistinctPlaceName ? (
                <p className="text-xs text-slate-500">{pickerPlaceName}</p>
              ) : null}
            </div>
          ) : (
            <div className="space-y-0.5">
              <p className="text-xs font-semibold text-slate-900">
                No map point selected
              </p>
              <p className="text-xs leading-snug text-slate-600">
                Choose a map point for this 999 call before submitting.
              </p>
            </div>
          )}
          {locationError ? (
            <p className="mt-1 text-xs text-red-600" role="alert">
              {locationError}
            </p>
          ) : null}
        </div>

        <div className="shrink-0 rounded-lg border border-slate-100 bg-slate-50/40 px-2.5 py-1.5">
          <p className="text-xs font-medium text-slate-700">
            Optional location details
          </p>
          <div className="mt-1.5 grid gap-2 sm:grid-cols-2">
            <div>
              <FieldLabel
                htmlFor="gateway-address"
                className={compactLabelClassName}
              >
                Location Name or Address
              </FieldLabel>
              <input
                id="gateway-address"
                type="text"
                value={addressText}
                onChange={(event) => onAddressTextChange(event.target.value)}
                disabled={isSubmitting}
                className={compactFieldClassName}
                placeholder="Building, road, or landmark description"
              />
            </div>
            <div>
              <FieldLabel htmlFor="gateway-place" className={compactLabelClassName}>
                Place Name
              </FieldLabel>
              <input
                id="gateway-place"
                type="text"
                value={placeName}
                onChange={(event) => onPlaceNameChange(event.target.value)}
                disabled={isSubmitting}
                className={compactFieldClassName}
                placeholder="Optional landmark or place name"
              />
            </div>
          </div>
        </div>
      </div>
    </CommandSectionCard>
  );
}
