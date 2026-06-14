"use client";

import {
  formatReportedCoordinates,
  getValidReportedCoordinates,
} from "@/components/dispatcher/triage/reportedLocationCoords";
import { AdminAreaInfo } from "@/components/location/AdminAreaInfo";

export type LocationInfoBlockProps = {
  addressText?: string | null;
  placeName?: string | null;
  latitude?: number | null;
  longitude?: number | null;
  adminAreaId?: number | null;
  showCoordinates?: boolean;
  detailedAdminArea?: boolean;
  addressClassName?: string;
  className?: string;
  fallbackText?: string | null;
};

export function LocationInfoBlock({
  addressText,
  placeName,
  latitude,
  longitude,
  adminAreaId,
  showCoordinates = true,
  detailedAdminArea = false,
  addressClassName = "text-sm text-slate-900",
  className = "",
  fallbackText = null,
}: LocationInfoBlockProps) {
  const trimmedAddress = addressText?.trim() ?? "";
  const trimmedPlace = placeName?.trim() ?? "";
  const showPlaceName =
    trimmedPlace.length > 0 && trimmedPlace !== trimmedAddress;
  const coordinates = getValidReportedCoordinates(
    latitude ?? undefined,
    longitude ?? undefined,
  );
  const primaryText = trimmedAddress || trimmedPlace || fallbackText;

  if (!primaryText && adminAreaId == null && !coordinates) {
    return null;
  }

  return (
    <div className={`min-w-0 flex-1 ${className}`.trim()}>
      {primaryText ? <p className={addressClassName}>{primaryText}</p> : null}
      {showPlaceName ? (
        <p className="mt-0.5 text-xs text-slate-500">{trimmedPlace}</p>
      ) : null}
      <AdminAreaInfo
        adminAreaId={adminAreaId}
        className="mt-0.5"
        detailed={detailedAdminArea}
      />
      {showCoordinates && coordinates ? (
        <p className="mt-0.5 text-xs text-slate-500">
          {formatReportedCoordinates(
            coordinates.latitude,
            coordinates.longitude,
          )}
        </p>
      ) : null}
    </div>
  );
}
