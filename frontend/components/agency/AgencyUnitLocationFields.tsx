"use client";

import dynamic from "next/dynamic";
import { useCallback, useEffect, useMemo, useState } from "react";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import type {
  LocationPickerSelectionDetails,
  LocationPickerValue,
} from "@/components/location/LocationPicker";
import type { IntakeStructuredLocation } from "@/types/intake";

const LocationPicker = dynamic(
  () =>
    import("@/components/location/LocationPicker").then((mod) => ({
      default: mod.LocationPicker,
    })),
  { ssr: false, loading: () => <p className="text-sm text-slate-500">Loading map…</p> },
);

type AgencyUnitLocationFieldsProps = {
  location: IntakeStructuredLocation | null;
  onLocationChange: (location: IntakeStructuredLocation | null) => void;
  disabled?: boolean;
};

export function AgencyUnitLocationFields({
  location,
  onLocationChange,
  disabled = false,
}: AgencyUnitLocationFieldsProps) {
  const [addressText, setAddressText] = useState("");
  const [placeName, setPlaceName] = useState("");

  useEffect(() => {
    setAddressText(location?.address_text ?? "");
    setPlaceName(location?.place_name ?? "");
  }, [location?.latitude, location?.longitude, location?.address_text, location?.place_name]);

  const pickerValue: LocationPickerValue | null = location
    ? { latitude: location.latitude, longitude: location.longitude }
    : null;

  const applyLocation = useCallback(
    (next: IntakeStructuredLocation | null) => {
      onLocationChange(next);
    },
    [onLocationChange],
  );

  const handlePickerChange = useCallback(
    (value: LocationPickerValue, details?: LocationPickerSelectionDetails) => {
      const next: IntakeStructuredLocation = {
        latitude: value.latitude,
        longitude: value.longitude,
        address_text: details?.addressText?.trim() || addressText.trim() || undefined,
        place_name: details?.placeName?.trim() || placeName.trim() || undefined,
        source: "manual_entry",
      };
      if (details?.addressText) setAddressText(details.addressText);
      if (details?.placeName) setPlaceName(details.placeName);
      applyLocation(next);
    },
    [addressText, applyLocation, placeName],
  );

  const handleAddressBlur = () => {
    if (!location) return;
    applyLocation({
      ...location,
      address_text: addressText.trim() || undefined,
      place_name: placeName.trim() || undefined,
      source: location.source ?? "manual_entry",
    });
  };

  const handlePlaceNameBlur = () => {
    if (!location) return;
    applyLocation({
      ...location,
      address_text: addressText.trim() || undefined,
      place_name: placeName.trim() || undefined,
      source: location.source ?? "manual_entry",
    });
  };

  const helperMessage = useMemo(() => {
    if (!location) return null;
    if (location.address_text?.trim() || location.place_name?.trim()) {
      return "Location selected. Review the map position before saving.";
    }
    return "Map location selected. You can adjust the address or place name manually.";
  }, [location]);

  return (
    <div className="space-y-3">
      <LocationPicker
        value={pickerValue}
        onChange={handlePickerChange}
        selectedAddress={addressText}
        selectedPlaceName={placeName}
        showCurrentLocation={false}
        showSelectionSummary={false}
        scrollWheelZoom={false}
        embedded
        mapClassName="h-[min(380px,42vh)] min-h-[260px] w-full rounded-xl"
        disabled={disabled}
      />
      {helperMessage ? (
        <p className="text-xs text-slate-500">{helperMessage}</p>
      ) : null}
      <div>
        <FieldLabel htmlFor="unit-base-address">Address / Road / Area</FieldLabel>
        <input
          id="unit-base-address"
          value={addressText}
          onChange={(event) => setAddressText(event.target.value)}
          onBlur={handleAddressBlur}
          className={triageFieldClassName}
          disabled={disabled}
          placeholder="Street, road, or area"
        />
      </div>
      <div>
        <FieldLabel htmlFor="unit-base-place">Place Name / Landmark</FieldLabel>
        <input
          id="unit-base-place"
          value={placeName}
          onChange={(event) => setPlaceName(event.target.value)}
          onBlur={handlePlaceNameBlur}
          className={triageFieldClassName}
          disabled={disabled}
          placeholder="Optional landmark or place name"
        />
      </div>
    </div>
  );
}
