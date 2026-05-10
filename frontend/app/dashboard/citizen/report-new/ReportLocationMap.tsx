"use client";

import { useEffect, useRef } from "react";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

const DEFAULT_CENTER: [number, number] = [23.8103, 90.4125];
const DEFAULT_ZOOM = 13;

type Props = {
  latitude: number | null;
  longitude: number | null;
  onPositionChange: (lat: number, lng: number) => void;
};

export function ReportLocationMap({ latitude, longitude, onPositionChange }: Props) {
  const mapElRef = useRef<HTMLDivElement>(null);
  const mapInstanceRef = useRef<L.Map | null>(null);
  const markerRef = useRef<L.CircleMarker | null>(null);

  useEffect(() => {
    const el = mapElRef.current;
    if (!el || mapInstanceRef.current) return;

    const map = L.map(el).setView(DEFAULT_CENTER, DEFAULT_ZOOM);
    mapInstanceRef.current = map;

    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution: "&copy; OpenStreetMap contributors",
      maxZoom: 19,
    }).addTo(map);

    map.on("click", (e: L.LeafletMouseEvent) => {
      const { lat, lng } = e.latlng;
      onPositionChange(lat, lng);
      if (markerRef.current) {
        markerRef.current.setLatLng([lat, lng]);
      } else {
        markerRef.current = L.circleMarker([lat, lng], {
          radius: 8,
          color: "#1d4ed8",
          weight: 2,
          fillColor: "#3b82f6",
          fillOpacity: 0.9,
        }).addTo(map);
      }
    });

    return () => {
      map.remove();
      mapInstanceRef.current = null;
      markerRef.current = null;
    };
  }, [onPositionChange]);

  useEffect(() => {
    const map = mapInstanceRef.current;
    if (!map) return;

    if (latitude == null || longitude == null) {
      if (markerRef.current) {
        map.removeLayer(markerRef.current);
        markerRef.current = null;
      }
      return;
    }

    if (markerRef.current) {
      markerRef.current.setLatLng([latitude, longitude]);
    } else {
      markerRef.current = L.circleMarker([latitude, longitude], {
        radius: 8,
        color: "#1d4ed8",
        weight: 2,
        fillColor: "#3b82f6",
        fillOpacity: 0.9,
      }).addTo(map);
    }
    map.setView([latitude, longitude], Math.max(map.getZoom(), 14));
  }, [latitude, longitude]);

  return (
    <div className="overflow-hidden rounded-lg border border-gray-300">
      <div ref={mapElRef} className="h-[280px] w-full bg-slate-100" />
    </div>
  );
}
