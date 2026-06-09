"use client";

import type { CSSProperties } from "react";
import { useMemo } from "react";
import { useDeclaredNationalDisasters } from "@/hooks/useDeclaredNationalDisasters";
import { buildDisasterHeadline } from "@/lib/national-disaster-alert";

export function NationalDisasterHeroAlert() {
  const { disasters: declaredDisasters } = useDeclaredNationalDisasters();

  const headlines = useMemo(
    () => declaredDisasters.map((disaster) => buildDisasterHeadline(disaster)),
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
