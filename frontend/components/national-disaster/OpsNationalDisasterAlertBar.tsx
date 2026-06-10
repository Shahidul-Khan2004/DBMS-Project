"use client";

import Link from "next/link";
import { ArrowRight } from "lucide-react";
import { useDeclaredNationalDisasters } from "@/hooks/useDeclaredNationalDisasters";
import type { UserRole } from "@/lib/auth-store";
import {
  buildDisasterSummaryLine,
  getOpsDisasterDetailPath,
} from "@/lib/national-disaster-alert";

export function OpsNationalDisasterAlertBar({ role }: { role: UserRole }) {
  const { disasters } = useDeclaredNationalDisasters();

  if (disasters.length === 0) return null;

  const primary = disasters[0];
  const summary = buildDisasterSummaryLine(primary);
  const extraCount = disasters.length - 1;
  const detailHref = getOpsDisasterDetailPath(
    role,
    primary.disaster_public_uuid,
  );

  return (
    <aside
      className="flex h-9 shrink-0 items-center gap-x-3 border-b border-[#991B1B]/30 bg-[#B91C1C]/95 px-4 text-white sm:px-6 lg:px-8 2xl:px-10"
      aria-label="National disaster alert"
      role="status"
    >
      <div className="flex shrink-0 items-center gap-2">
        <span className="text-[0.65rem] font-black uppercase leading-none tracking-[0.14em] sm:text-xs">
          Disaster alert
        </span>
        <span className="inline-flex items-center rounded-full bg-white px-2 py-0.5 text-[0.6rem] font-black uppercase leading-none tracking-[0.1em] text-[#991B1B] sm:text-[0.65rem]">
          Live
        </span>
      </div>
      <p className="m-0 min-w-0 flex-1 truncate text-xs font-medium leading-none sm:text-sm">
        {summary}
        {extraCount > 0 ? (
          <span className="text-white/85">{` · +${extraCount} more`}</span>
        ) : null}
      </p>
      <Link
        href={detailHref}
        className="inline-flex shrink-0 items-center gap-1 text-xs font-semibold leading-none text-white transition hover:text-white/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/80 focus-visible:ring-offset-1 focus-visible:ring-offset-[#B91C1C] sm:text-sm"
      >
        Open
        <ArrowRight className="h-3.5 w-3.5" aria-hidden />
      </Link>
    </aside>
  );
}
