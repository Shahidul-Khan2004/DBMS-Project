"use client";

import { MapPin } from "lucide-react";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { formatIncidentStatus } from "@/lib/incident-status";
import { getSeverityBadgeTone } from "@/components/dispatcher/incidents/severityStyles";
import type { IncidentDetailResponse } from "@/types/incident-command";

function SummaryTextButton({
  label,
  onClick,
  disabled = false,
}: {
  label: string;
  onClick: () => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="shrink-0 text-sm font-medium text-[#006747] transition hover:text-[#002D62] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#006747]/30 focus-visible:ring-offset-1 disabled:cursor-not-allowed disabled:text-slate-400 disabled:hover:text-slate-400"
    >
      {label}
    </button>
  );
}

export function IncidentCommandSummaryCard({
  detail,
  canEditLocation = false,
  onOpenDetails,
  onEditLocation,
  className = "",
}: {
  detail: IncidentDetailResponse;
  canEditLocation?: boolean;
  onOpenDetails: () => void;
  onEditLocation: () => void;
  className?: string;
}) {
  const locationText =
    detail.overview.locationText?.trim() || "No location recorded";

  return (
    <section
      className={`rounded-xl border border-slate-200/90 bg-white p-3 shadow-sm sm:p-4 ${className}`.trim()}
    >
      <div className="min-w-0 space-y-0.5">
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="text-lg font-semibold text-slate-900">
            {detail.title}
          </h1>
          <Badge tone={getSeverityBadgeTone(detail.severity)}>
            {formatBadgeLabel(detail.severity)}
          </Badge>
          <Badge tone={detail.status}>
            {formatIncidentStatus(detail.status)}
          </Badge>
        </div>

        <p className="text-sm text-slate-600">
          <span className="font-medium text-slate-700">
            {detail.incidentCode}
          </span>
          <span className="text-slate-400"> · </span>
          {detail.categoryLabel}
          <span className="text-slate-400"> · </span>
          Reported {detail.reportedAgeLabel}
        </p>
      </div>

      <div className="flex flex-col gap-1.5 pt-0.5 sm:flex-row sm:items-center sm:gap-3">
        <p className="flex min-w-0 flex-1 items-center gap-1 text-sm text-slate-600">
          <MapPin
            className="h-3.5 w-3.5 shrink-0 text-slate-400"
            aria-hidden
          />
          <span className="min-w-0 truncate">{locationText}</span>
        </p>
        <div
          className="flex shrink-0 flex-wrap items-center gap-x-3 gap-y-1 sm:justify-end"
          role="group"
          aria-label="Location actions"
        >
          <SummaryTextButton label="View Details" onClick={onOpenDetails} />
          <SummaryTextButton
            label="Edit Location"
            onClick={onEditLocation}
            disabled={!canEditLocation}
          />
        </div>
      </div>
    </section>
  );
}
