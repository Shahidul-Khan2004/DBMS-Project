"use client";

import { LocationInfoBlock } from "@/components/location/LocationInfoBlock";

type LocationLike = {
  address_text?: string | null;
  place_name?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  admin_area_id?: number | null;
} | null | undefined;

type LocationSummaryProps = {
  location: LocationLike;
  fallbackText?: string;
  className?: string;
  addressClassName?: string;
  showCoordinates?: boolean;
};

export function getLocationPrimaryText(
  location: LocationLike,
  fallbackText = "Map location selected",
): string {
  if (!location) return "-";
  return (
    location.address_text?.trim() ||
    location.place_name?.trim() ||
    fallbackText
  );
}

export function LocationSummary({
  location,
  fallbackText = "Map location selected",
  className = "",
  addressClassName,
  showCoordinates = false,
}: LocationSummaryProps) {
  if (!location) {
    return <span className={className}>-</span>;
  }

  return (
    <LocationInfoBlock
      addressText={location.address_text}
      placeName={location.place_name}
      latitude={location.latitude}
      longitude={location.longitude}
      adminAreaId={location.admin_area_id}
      fallbackText={fallbackText}
      showCoordinates={showCoordinates}
      addressClassName={addressClassName}
      className={className}
    />
  );
}
