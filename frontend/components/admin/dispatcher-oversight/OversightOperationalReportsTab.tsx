"use client";

import Link from "next/link";
import { BarChart3, ChevronRight, Clock } from "lucide-react";
import { getDispatcherClickableCardRowClasses } from "@/components/dispatcher/listRowHoverStyles";

const REPORT_CARDS = [
  {
    id: "workload",
    title: "Agency Workload",
    description:
      "Review agency capacity, active incidents, and unit availability from operations workload data.",
    icon: BarChart3,
    href: "/dashboard/admin/reports",
  },
  {
    id: "timing",
    title: "Response Timing",
    description:
      "Review per-incident pipeline timing from call through agency response.",
    icon: Clock,
    href: "/dashboard/admin/reports",
  },
] as const;

export function OversightOperationalReportsTab() {
  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-slate-600">
        Full workload and response timing tools live under Reports.
      </p>
      <ul className="flex flex-col gap-2">
        {REPORT_CARDS.map((card) => {
          const Icon = card.icon;
          return (
            <li key={card.id}>
              <Link
                href={card.href}
                className={`group flex w-full flex-wrap items-center justify-between gap-3 rounded-xl border px-4 py-3 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[#002D62] ${getDispatcherClickableCardRowClasses()}`}
              >
                <div className="flex min-w-0 flex-1 items-start gap-3">
                  <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-[#002D62]">
                    <Icon className="h-4 w-4" aria-hidden />
                  </span>
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-slate-900">
                      {card.title}
                    </p>
                    <p className="mt-0.5 text-xs text-slate-600">
                      {card.description}
                    </p>
                  </div>
                </div>
                <span className="flex shrink-0 items-center gap-0.5 text-xs font-medium text-[#002D62]">
                  Open Reports
                  <ChevronRight
                    className="h-4 w-4 transition-transform group-hover:translate-x-0.5"
                    aria-hidden
                  />
                </span>
              </Link>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
