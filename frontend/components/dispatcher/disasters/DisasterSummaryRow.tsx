"use client";

import Link from "next/link";
import { ChevronRight } from "lucide-react";
import { getDispatcherClickableCardRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { dispatcherNationalDisasterDetailPath } from "@/lib/dispatcher-national-disaster-routes";
import {
  formatDisasterEventTypeLabel,
  formatDisasterSeverityLabel,
  formatDisasterStatusLabel,
} from "@/lib/disaster-operations-format";
import type { OperationsDisasterSummary } from "@/lib/disaster-operations-types";

export function DisasterSummaryRow({
  disaster,
}: {
  disaster: OperationsDisasterSummary;
}) {
  const uuid = disaster.public_uuid;
  if (!uuid) return null;

  return (
    <li>
      <Link
        href={dispatcherNationalDisasterDetailPath(uuid)}
        className={`group flex w-full flex-wrap items-center justify-between gap-3 rounded-xl border px-4 py-3 text-left focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[#002D62] ${getDispatcherClickableCardRowClasses()}`}
      >
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-slate-900">{disaster.title}</p>
          <p className="mt-0.5 text-xs text-slate-600">{disaster.event_code}</p>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          <Badge size="compact" tone="neutral">
            {formatBadgeLabel(
              formatDisasterEventTypeLabel(
                disaster.event_type_code,
                disaster.event_type_name,
              ),
            )}
          </Badge>
          {disaster.severity_level ? (
            <Badge size="compact" tone="warning">
              {formatBadgeLabel(
                formatDisasterSeverityLabel(disaster.severity_level),
              )}
            </Badge>
          ) : null}
          <Badge size="compact" tone="active">
            {formatBadgeLabel(formatDisasterStatusLabel(disaster.status_code))}
          </Badge>
          <span className="flex items-center gap-0.5 text-xs font-medium text-[#002D62]">
            Open Disaster
            <ChevronRight
              className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5"
              aria-hidden
            />
          </span>
        </div>
      </Link>
    </li>
  );
}
