"use client";

import dynamic from "next/dynamic";
import { CommandPlaceholderAction } from "@/components/dispatcher/incidents/command/CommandPlaceholderAction";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { formatBadgeLabel } from "@/components/ui/Badge";
import { formatBangladeshTime } from "@/lib/datetime";
import { formatIncidentStatus } from "@/lib/incident-status";
import type { IncidentDetailResponse } from "@/types/incident-command";

const EDIT_DETAILS_MESSAGE =
  "Incident detail editing will be available in a later phase.";
const ReportedLocationMapPreview = dynamic(
  () =>
    import("@/components/dispatcher/triage/ReportedLocationMapPreview").then(
      (mod) => ({ default: mod.ReportedLocationMapPreview }),
    ),
  {
    ssr: false,
    loading: () => (
      <div className="h-36 w-full animate-pulse rounded-lg bg-slate-100" />
    ),
  },
);

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs font-medium text-slate-500">{label}</dt>
      <dd className="mt-0.5 text-sm text-slate-800">{value}</dd>
    </div>
  );
}

export function IncidentCommandOverviewCard({
  detail,
  sourceLabel,
  className = "",
}: {
  detail: IncidentDetailResponse;
  sourceLabel: string;
  className?: string;
}) {
  const { overview } = detail;
  const location = overview.location;

  return (
    <CommandSectionCard
      title="Incident Overview"
      headerAction={
        <CommandPlaceholderAction
          label="Edit Details"
          comingSoonMessage={EDIT_DETAILS_MESSAGE}
        />
      }
      className={className}
      fillHeight
      scrollableBody
    >
      <p className="text-sm font-semibold text-slate-900">{overview.title}</p>
      <p className="mt-2 text-sm leading-6 text-slate-700">
        {overview.description?.trim() ||
          "No additional description provided."}
      </p>

      <dl className="mt-4 grid gap-3 sm:grid-cols-2">
        <DetailRow label="Category" value={overview.categoryLabel} />
        <DetailRow
          label="Severity"
          value={formatBadgeLabel(overview.severity)}
        />
        <DetailRow
          label="Status"
          value={formatIncidentStatus(overview.status)}
        />
        <DetailRow label="Source" value={sourceLabel} />
        <DetailRow label="Incident code" value={detail.incidentCode} />
        <DetailRow
          label="Reported"
          value={
            overview.reportedAt
              ? formatBangladeshTime(overview.reportedAt)
              : "Unknown"
          }
        />
      </dl>

      <div className="mt-5 border-t border-slate-100 pt-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            Location
          </h4>
          <div className="flex flex-wrap items-center gap-2">
            <CommandPlaceholderAction
              label="Edit Location"
              comingSoonMessage="Edit location from the incident command header or details drawer."
            />
            <CommandPlaceholderAction
              label="View Location History"
              comingSoonMessage="View location history from the incident details drawer."
            />
          </div>
        </div>
        <p className="mt-2 text-sm text-slate-800">
          {overview.locationText?.trim() || "No location recorded"}
        </p>
        {location ? (
          <div className="mt-3 max-h-36 overflow-hidden rounded-lg">
            <ReportedLocationMapPreview
              latitude={location.latitude}
              longitude={location.longitude}
              addressText={location.addressText ?? undefined}
              placeName={location.placeName ?? undefined}
              previewKey={detail.incidentCode}
            />
          </div>
        ) : null}
      </div>
    </CommandSectionCard>
  );
}
