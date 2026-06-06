"use client";

import { useEffect, useState } from "react";
import { listPublicDisasters } from "@/lib/public-disasters-api";
import type { PublicDisaster } from "@/types/public-disaster";

function formatDetail(value?: string | null) {
  if (!value) return null;
  return value
    .split(/[_\s-]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1).toLowerCase())
    .join(" ");
}

export function AgencyNationalDisasterBanner() {
  const [declaredDisasters, setDeclaredDisasters] = useState<PublicDisaster[]>([]);

  useEffect(() => {
    let cancelled = false;

    async function loadDisasters() {
      try {
        const data = await listPublicDisasters();
        if (cancelled) return;
        setDeclaredDisasters(
          data.disasters.filter((d) => d.disaster_status === "declared"),
        );
      } catch {
        if (!cancelled) setDeclaredDisasters([]);
      }
    }

    void loadDisasters();
    const intervalId = window.setInterval(loadDisasters, 60000);
    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, []);

  if (declaredDisasters.length === 0) return null;

  const primary = declaredDisasters[0];
  const disasterType = formatDetail(primary.disaster_type_name) ?? "Disaster";
  const severity = formatDetail(primary.severity_level) ?? "Unspecified";

  return (
    <div
      className="mb-4 shrink-0 rounded-xl border border-[#991B1B]/30 bg-[#B91C1C]/95 px-4 py-3 text-white shadow-sm"
      role="status"
      aria-label="National disaster alert"
    >
      <p className="text-xs font-semibold uppercase tracking-wide text-white/90">
        Declared national disaster
      </p>
      <p className="mt-1 text-sm font-semibold">{primary.title}</p>
      <p className="mt-0.5 text-xs text-white/90">
        {disasterType} · Severity {severity}
        {primary.public_guidance ? ` · ${primary.public_guidance}` : ""}
      </p>
      {declaredDisasters.length > 1 ? (
        <p className="mt-1 text-xs text-white/80">
          +{declaredDisasters.length - 1} additional declared event
          {declaredDisasters.length > 2 ? "s" : ""}
        </p>
      ) : null}
    </div>
  );
}
