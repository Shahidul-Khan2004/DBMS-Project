"use client";

import dynamic from "next/dynamic";
import { useEffect, useState } from "react";
import { X } from "lucide-react";
import {
  formatReportedCoordinates,
  getValidReportedCoordinates,
} from "@/components/dispatcher/triage/reportedLocationCoords";
import { AdminAreaInfo } from "@/components/location/AdminAreaInfo";
import { Button } from "@/components/ui/Button";
import { ModalPortal } from "@/components/ui/ModalPortal";

const ReportedLocationMapPreview = dynamic(
  () =>
    import("@/components/dispatcher/triage/ReportedLocationMapPreview").then(
      (mod) => ({ default: mod.ReportedLocationMapPreview }),
    ),
  {
    ssr: false,
    loading: () => (
      <div className="h-[min(50vh,320px)] w-full animate-pulse rounded-lg bg-slate-100" />
    ),
  },
);

const MapPreviewUnavailable = dynamic(
  () =>
    import("@/components/dispatcher/triage/ReportedLocationMapPreview").then(
      (mod) => ({ default: mod.MapPreviewUnavailable }),
    ),
  { ssr: false },
);

const DEFAULT_BUTTON_CLASS =
  "inline-flex h-9 items-center justify-center whitespace-nowrap rounded-full border border-[#002D62]/20 bg-[#EFF6FF] px-4 text-xs font-semibold text-[#002D62] transition-colors hover:border-[#002D62]/30 hover:bg-[#DCEBFF]";

export type LocationMapModalProps = {
  open: boolean;
  onClose: () => void;
  latitude?: number;
  longitude?: number;
  title?: string;
  addressText?: string;
  placeName?: string;
  adminAreaId?: number | null;
  previewKey?: string;
};

function getLocationSubtitle(
  addressText?: string,
  placeName?: string,
): string | null {
  if (addressText && placeName && addressText !== placeName) {
    return `${placeName} · ${addressText}`;
  }
  return addressText || placeName || null;
}

export function LocationMapModal({
  open,
  onClose,
  latitude,
  longitude,
  title = "Location map",
  addressText,
  placeName,
  adminAreaId,
  previewKey,
}: LocationMapModalProps) {
  const coordinates = getValidReportedCoordinates(latitude, longitude);
  const subtitle = getLocationSubtitle(addressText, placeName);

  useEffect(() => {
    if (!open) return;

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <ModalPortal
      open={open}
      className="fixed inset-0 z-50 flex items-center justify-center px-4"
    >
      <button
        type="button"
        aria-label="Close location map"
        className="absolute inset-0 bg-black/40"
        onClick={onClose}
      />
      <div
        aria-labelledby="location-map-title"
        className="relative z-10 flex max-h-[90vh] w-full max-w-lg flex-col overflow-hidden rounded-xl border border-slate-200 bg-white shadow-xl"
      >
        <div className="border-b border-slate-100 px-5 py-4">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <h2
                id="location-map-title"
                className="text-lg font-semibold text-slate-900"
              >
                {title}
              </h2>
              {subtitle ? (
                <p className="mt-1 text-sm text-slate-600">{subtitle}</p>
              ) : null}
              <AdminAreaInfo adminAreaId={adminAreaId} className="mt-1" />
              {coordinates ? (
                <p className="mt-1 text-xs text-slate-500">
                  {formatReportedCoordinates(
                    coordinates.latitude,
                    coordinates.longitude,
                  )}
                </p>
              ) : null}
            </div>
            <button
              type="button"
              onClick={onClose}
              className="inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-slate-500 transition-colors hover:bg-slate-100 hover:text-slate-700"
              aria-label="Close"
            >
              <X className="h-4 w-4" aria-hidden />
            </button>
          </div>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          {coordinates ? (
            <ReportedLocationMapPreview
              previewKey={previewKey}
              latitude={coordinates.latitude}
              longitude={coordinates.longitude}
              addressText={addressText}
              placeName={placeName}
              heightClassName="h-[min(50vh,320px)]"
            />
          ) : (
            <MapPreviewUnavailable heightClassName="h-[min(50vh,320px)]" />
          )}
        </div>

        <div className="flex justify-end border-t border-slate-100 px-5 py-4">
          <Button type="button" variant="secondary" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </ModalPortal>
  );
}

export type OpenLocationMapButtonProps = {
  latitude?: number;
  longitude?: number;
  previewKey?: string;
  title?: string;
  addressText?: string;
  placeName?: string;
  adminAreaId?: number | null;
  label?: string;
  className?: string;
  disabled?: boolean;
};

export function OpenLocationMapButton({
  latitude,
  longitude,
  previewKey,
  title,
  addressText,
  placeName,
  adminAreaId,
  label = "Open map",
  className = DEFAULT_BUTTON_CLASS,
  disabled = false,
}: OpenLocationMapButtonProps) {
  const [open, setOpen] = useState(false);
  const hasValidCoordinates =
    getValidReportedCoordinates(latitude, longitude) != null;
  const isDisabled = disabled || !hasValidCoordinates;

  return (
    <>
      <button
        type="button"
        className={className}
        disabled={isDisabled}
        onClick={() => setOpen(true)}
      >
        {label}
      </button>
      <LocationMapModal
        open={open}
        onClose={() => setOpen(false)}
        latitude={latitude}
        longitude={longitude}
        previewKey={previewKey}
        title={title}
        addressText={addressText}
        placeName={placeName}
        adminAreaId={adminAreaId}
      />
    </>
  );
}
