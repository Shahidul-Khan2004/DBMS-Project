"use client";

import { getDispatcherSelectableRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { formatReadableLabel } from "@/lib/agency-dispatch-utils";
import { getIncidentLatestUpdateLabel } from "@/lib/agency-incident-utils";
import type { GroupedAgencyIncident } from "@/lib/agency-incident-utils";

type AgencyIncidentRowProps = {
  incident: GroupedAgencyIncident;
  selected?: boolean;
  onSelect: (incident: GroupedAgencyIncident) => void;
};

export function AgencyIncidentRow({
  incident,
  selected = false,
  onSelect,
}: AgencyIncidentRowProps) {
  const latestLabel = getIncidentLatestUpdateLabel(incident.latestUpdateAt);
  const statusLabel = incident.statusCode
    ? formatReadableLabel(incident.statusCode)
    : null;
  const participationLabel = incident.participationStatus
    ? formatReadableLabel(incident.participationStatus)
    : null;

  return (
    <article
      className={`rounded-xl border p-3 ${getDispatcherSelectableRowClasses({
        selected,
        variant: "card",
      })}`}
      onClick={() => onSelect(incident)}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onSelect(incident);
        }
      }}
      role="button"
      tabIndex={0}
      aria-pressed={selected}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold text-slate-900">{incident.title}</p>
          <p className="mt-0.5 text-xs text-slate-600">{incident.incidentCode}</p>
        </div>
        <div className="flex shrink-0 flex-wrap items-center justify-end gap-1">
          {incident.highestPriority ? (
            <Badge tone={incident.highestPriority}>
              {formatBadgeLabel(incident.highestPriority)}
            </Badge>
          ) : null}
          {statusLabel ? <Badge tone={incident.statusCode}>{statusLabel}</Badge> : null}
        </div>
      </div>

      {participationLabel ? (
        <p className="mt-1.5 text-xs text-slate-600">{participationLabel}</p>
      ) : null}

      <p className="mt-2 text-xs text-slate-600">
        {incident.assignedUnitCount} assigned unit
        {incident.assignedUnitCount === 1 ? "" : "s"}
        {incident.latestUpdateAt ? ` · latest update ${latestLabel}` : null}
      </p>
    </article>
  );
}
