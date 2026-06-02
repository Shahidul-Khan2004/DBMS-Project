"use client";

import { MapPin } from "lucide-react";
import Link from "next/link";
import { getDispatcherClickableCardRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import {
  getSeverityBadgeTone,
  getSeverityCardAccentMuted,
} from "@/components/dispatcher/incidents/severityStyles";
import type {
  ActiveIncidentListItem,
  IncidentCardLocationState,
} from "@/components/dispatcher/incidents/types";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { formatRelativeAge } from "@/lib/format-relative-age";
import { formatIncidentOriginSourceFallbackLabel } from "@/lib/incident-source-label";
import { formatIncidentStatus } from "@/lib/incident-status";
import type { OperationsIncidentRow } from "@/lib/operations-intake-triage";

interface ArchiveIncidentRowProps {
  incident: ActiveIncidentListItem;
  sourceRow: OperationsIncidentRow;
  locationState: IncidentCardLocationState;
}

function getLocationDisplay(state: IncidentCardLocationState): {
  text: string;
  title?: string;
  isLoading: boolean;
} {
  switch (state.status) {
    case "loaded":
      return { text: state.address, title: state.address, isLoading: false };
    case "empty":
      return { text: "No location recorded", isLoading: false };
    case "error":
      return { text: "Location could not be loaded", isLoading: false };
    case "loading":
    case "idle":
    default:
      return { text: "Loading location…", isLoading: true };
  }
}

function getTerminalTimeLabel(row: OperationsIncidentRow): string | null {
  const status = row.status_code?.trim().toLowerCase();
  if (status === "resolved" && row.resolved_at) {
    return `Resolved ${formatRelativeAge(row.resolved_at)}`;
  }
  if (status === "closed" && row.closed_at) {
    return `Closed ${formatRelativeAge(row.closed_at)}`;
  }
  if (row.updated_at) {
    return `Updated ${formatRelativeAge(row.updated_at)}`;
  }
  return null;
}

export function ArchiveIncidentRow({
  incident,
  sourceRow,
  locationState,
}: ArchiveIncidentRowProps) {
  const commandHref = `/dashboard/dispatcher/incidents/${encodeURIComponent(incident.publicUuid)}`;
  const reportedAgeLabel =
    incident.reportedAgeLabel ?? formatRelativeAge(incident.reportedAt);
  const locationDisplay = getLocationDisplay(locationState);
  const terminalTimeLabel = getTerminalTimeLabel(sourceRow);
  const originLabel = sourceRow.origin_type?.trim()
    ? formatIncidentOriginSourceFallbackLabel(sourceRow.origin_type)
    : null;

  return (
    <Link
      href={commandHref}
      className={`group block rounded-xl border p-2.5 sm:p-3.5 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62] ${getSeverityCardAccentMuted(incident.severity)} ${getDispatcherClickableCardRowClasses()}`}
    >
      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <Badge tone={getSeverityBadgeTone(incident.severity)}>
              {formatBadgeLabel(incident.severity)}
            </Badge>
            <span className="inline-flex max-w-full items-center rounded-full bg-slate-100 px-2.5 py-1 text-xs font-medium text-slate-700 ring-1 ring-slate-200">
              {incident.categoryLabel}
            </span>
            <Badge tone={incident.status}>
              {formatIncidentStatus(incident.status)}
            </Badge>
          </div>
          <span className="shrink-0 text-xs font-medium text-slate-500">
            Reported {reportedAgeLabel}
          </span>
        </div>

        <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
          <div className="min-w-0 flex-1">
            <h3 className="text-sm font-semibold text-slate-900 sm:text-base">
              {incident.title}
            </h3>
            <p className="mt-1 font-mono text-xs text-slate-500">{incident.incidentCode}</p>
            <p className="mt-1.5 flex items-center gap-1 text-xs text-slate-500">
              <MapPin className="h-3.5 w-3.5 shrink-0 text-slate-400" aria-hidden />
              <span
                className={`min-w-0 truncate ${locationDisplay.isLoading ? "animate-pulse" : "text-slate-600"}`}
                title={locationDisplay.title}
              >
                {locationDisplay.text}
              </span>
            </p>
            {(terminalTimeLabel || originLabel) && (
              <p className="mt-1.5 text-xs text-slate-500">
                {terminalTimeLabel}
                {terminalTimeLabel && originLabel ? (
                  <span className="text-slate-300"> · </span>
                ) : null}
                {originLabel ? <span>{originLabel}</span> : null}
              </p>
            )}
          </div>
          <span className="text-sm font-medium text-[#002D62] transition-colors group-hover:text-[#001F4A] sm:shrink-0">
            Review Incident →
          </span>
        </div>
      </div>
    </Link>
  );
}
