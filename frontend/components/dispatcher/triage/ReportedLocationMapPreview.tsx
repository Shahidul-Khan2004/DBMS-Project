"use client";

import { useEffect, useRef, useState } from "react";
import {
  CircleMarker,
  MapContainer,
  TileLayer,
  useMap,
} from "react-leaflet";
import {
  formatReportedCoordinates,
  getValidReportedCoordinates,
} from "@/components/dispatcher/triage/reportedLocationCoords";

const PREVIEW_ZOOM = 15;

export type ReportedLocationMapPreviewProps = {
  latitude?: number;
  longitude?: number;
  addressText?: string;
  placeName?: string;
  /** Stable id (e.g. report uuid) combined with coords for clean remount on intake switch */
  previewKey?: string;
  /** Tailwind height class for the map container (default h-[180px]) */
  heightClassName?: string;
};

function MapRecenter({
  latitude,
  longitude,
}: {
  latitude: number;
  longitude: number;
}) {
  const map = useMap();
  const lastCenteredLocationRef = useRef<string | null>(null);

  useEffect(() => {
    const locationKey = `${latitude.toFixed(6)},${longitude.toFixed(6)}`;
    if (lastCenteredLocationRef.current === locationKey) return;

    lastCenteredLocationRef.current = locationKey;
    try {
      map.setView([latitude, longitude], PREVIEW_ZOOM);
    } catch {
      // Map may be tearing down during route/intake transitions.
    }
  }, [latitude, longitude, map]);

  return null;
}

function MapResizeHandler() {
  const map = useMap();

  useEffect(() => {
    let cancelled = false;

    const handleResize = () => {
      if (cancelled) return;
      const container = map.getContainer();
      if (!container?.isConnected) return;
      try {
        map.invalidateSize();
      } catch {
        // Ignore races while Leaflet unmounts.
      }
    };

    const resizeObserver = new ResizeObserver(handleResize);
    const mapContainer = map.getContainer();
    if (mapContainer) {
      resizeObserver.observe(mapContainer);
    }

    window.addEventListener("resize", handleResize);
    const timeoutId = window.setTimeout(handleResize, 100);

    return () => {
      cancelled = true;
      window.clearTimeout(timeoutId);
      window.removeEventListener("resize", handleResize);
      resizeObserver.disconnect();
    };
  }, [map]);

  return null;
}

export function MapPreviewUnavailable({
  heightClassName = "h-[180px]",
}: {
  heightClassName?: string;
}) {
  return (
    <div
      className={`flex w-full flex-col items-center justify-center rounded-lg border border-slate-200 bg-slate-50 px-4 text-center ${heightClassName}`}
    >
      <p className="text-sm font-medium text-slate-700">
        Map preview unavailable
      </p>
      <p className="mt-1 text-xs text-slate-500">
        This report does not include valid coordinates.
      </p>
    </div>
  );
}

function MapPreviewLoading({
  heightClassName = "h-[180px]",
}: {
  heightClassName?: string;
}) {
  return (
    <div
      className={`w-full animate-pulse rounded-lg bg-slate-100 ${heightClassName}`}
      aria-hidden
    />
  );
}

function ReportedLocationMapPreviewInner({
  latitude,
  longitude,
  previewKey,
  heightClassName = "h-[180px]",
}: ReportedLocationMapPreviewProps) {
  const coordinates = getValidReportedCoordinates(latitude, longitude);

  if (!coordinates) {
    return <MapPreviewUnavailable heightClassName={heightClassName} />;
  }

  const { latitude: lat, longitude: lng } = coordinates;
  const mapKey = previewKey
    ? `${previewKey}:${lat.toFixed(6)},${lng.toFixed(6)}`
    : `${lat.toFixed(6)},${lng.toFixed(6)}`;

  return (
    <div
      className="reported-location-map-preview relative isolate z-0 overflow-hidden rounded-lg border border-slate-200 bg-slate-100"
      aria-label={`Map preview for ${formatReportedCoordinates(lat, lng)}`}
    >
      <MapContainer
        key={mapKey}
        center={[lat, lng]}
        zoom={PREVIEW_ZOOM}
        scrollWheelZoom={false}
        dragging={false}
        doubleClickZoom={false}
        zoomControl={false}
        touchZoom={false}
        boxZoom={false}
        keyboard={false}
        className={`w-full ${heightClassName}`}
      >
        <TileLayer
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
          url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          maxZoom={19}
        />
        <MapRecenter latitude={lat} longitude={lng} />
        <MapResizeHandler />
        <CircleMarker
          center={[lat, lng]}
          radius={9}
          pathOptions={{
            color: "#ffffff",
            fillColor: "#DA291C",
            fillOpacity: 1,
            weight: 3,
          }}
        />
      </MapContainer>
    </div>
  );
}

export function ReportedLocationMapPreview(props: ReportedLocationMapPreviewProps) {
  const [isClientReady, setIsClientReady] = useState(false);

  useEffect(() => {
    setIsClientReady(true);
    return () => setIsClientReady(false);
  }, []);

  if (!isClientReady) {
    return <MapPreviewLoading heightClassName={props.heightClassName} />;
  }

  return <ReportedLocationMapPreviewInner {...props} />;
}
