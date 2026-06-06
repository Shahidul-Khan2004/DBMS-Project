"use client";

import type { CSSProperties } from "react";
import { useEffect, useMemo, useState } from "react";
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

function formatGuidance(value?: string | null) {
  const guidance = value?.trim().replace(/[\/\s]+$/u, "");
  if (!guidance) return null;
  return /[.!?]$/u.test(guidance) ? guidance : `${guidance}.`;
}

function buildHeadline(disaster: PublicDisaster) {
  const disasterType = formatDetail(disaster.disaster_type_name) ?? "Disaster";
  const severity = formatDetail(disaster.severity_level) ?? "Unspecified";
  const guidance = formatGuidance(disaster.public_guidance);

  return `NATIONAL DISASTER ALERT: ${disaster.title} — ${disasterType} emergency — Severity: ${severity}.${guidance ? ` ${guidance}` : ""}`;
}

export function NationalDisasterHeroAlert() {
  const [declaredDisasters, setDeclaredDisasters] = useState<PublicDisaster[]>(
    [],
  );

  useEffect(() => {
    let cancelled = false;

    async function loadDisasters() {
      try {
        const data = await listPublicDisasters();
        if (cancelled) return;

        setDeclaredDisasters(
          data.disasters.filter(
            (disaster) => disaster.disaster_status === "declared",
          ),
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

  const headlines = useMemo(
    () => declaredDisasters.map((disaster) => buildHeadline(disaster)),
    [declaredDisasters],
  );

  if (declaredDisasters.length === 0) return null;

  const combinedLength = headlines.join(" | ").length;
  const tickerStyle = {
    "--disaster-alert-duration": `${Math.max(combinedLength / 7, 18)}s`,
  } as CSSProperties;

  return (
    <aside
      className="national-disaster-alert flex min-h-14 w-full max-w-none overflow-hidden rounded-none border-y border-white/25 bg-[#B91C1C]/95 text-white shadow-xl shadow-black/20 focus-within:outline-none focus-within:ring-2 focus-within:ring-white/80 sm:min-h-16 lg:min-h-[72px]"
      aria-label="National disaster alert"
      tabIndex={0}
      style={tickerStyle}
    >
      <div className="flex shrink-0 items-center gap-2 border-r border-white/20 bg-[#7F1D1D]/90 px-3 py-3 sm:gap-3 sm:px-5">
        <span className="max-w-[9rem] text-xs font-black uppercase leading-tight tracking-[0.16em] text-white sm:max-w-[12rem] sm:text-sm lg:max-w-none lg:text-base">
          Official Disaster Alert
        </span>
        <span className="rounded-full bg-white px-2.5 py-1 text-[0.65rem] font-black uppercase tracking-[0.12em] text-[#991B1B] sm:text-xs">
          Live
        </span>
      </div>
      <div className="national-disaster-alert-viewport flex h-14 min-w-0 flex-1 items-center overflow-hidden sm:h-16 lg:h-[72px]">
        <div className="national-disaster-alert-track flex w-max items-center whitespace-nowrap">
          {[0, 1].map((groupIndex) => (
            <div
              aria-hidden={groupIndex === 1}
              className="national-disaster-alert-group flex shrink-0 items-center"
              key={groupIndex}
            >
              {headlines.map((headline, index) => (
                <span
                  className="national-disaster-alert-headline text-base font-black tracking-wide text-white sm:text-lg lg:text-xl"
                  key={`${headline}-${index}`}
                >
                  {headline}
                </span>
              ))}
            </div>
          ))}
        </div>
      </div>
    </aside>
  );
}
