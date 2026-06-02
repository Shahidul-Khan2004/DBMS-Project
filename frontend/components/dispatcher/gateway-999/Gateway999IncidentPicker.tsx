"use client";

import { FieldLegend } from "@/components/dispatcher/FieldLabel";
import { getDispatcherSelectableRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import { MapPin } from "lucide-react";
import {
  getSeverityBadgeTone,
  getSeverityCardAccent,
} from "@/components/dispatcher/incidents/severityStyles";
import type { Gateway999IncidentOption } from "@/components/dispatcher/gateway-999/types";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { formatRelativeAge } from "@/lib/format-relative-age";
import { formatIncidentStatus } from "@/lib/incident-status";

type Gateway999IncidentPickerProps = {
  incidents: Gateway999IncidentOption[];
  selectedUuid: string;
  isLoading?: boolean;
  error?: string | null;
  disabled?: boolean;
  onSelect: (publicUuid: string) => void;
  onRetry?: () => void;
};

export function Gateway999IncidentPicker({
  incidents,
  selectedUuid,
  isLoading = false,
  error = null,
  disabled = false,
  onSelect,
  onRetry,
}: Gateway999IncidentPickerProps) {
  return (
    <fieldset disabled={disabled}>
      <FieldLegend required>Selected Incident</FieldLegend>

      {isLoading ? (
        <div className="mt-1.5">
          <LoadingSkeleton lines={3} />
        </div>
      ) : error ? (
        <div className="mt-1.5 space-y-2">
          <ErrorAlert message={error} />
          {onRetry ? (
            <Button type="button" variant="secondary" size="sm" onClick={onRetry}>
              Retry
            </Button>
          ) : null}
        </div>
      ) : incidents.length === 0 ? (
        <p className="mt-1.5 text-sm text-slate-600">
          No active incidents are available to link.
        </p>
      ) : (
        <ul className="mt-1.5 max-h-[280px] space-y-1.5 overflow-y-auto pr-1">
          {incidents.map((incident) => {
            const selected = selectedUuid === incident.publicUuid;
            const reportedAgeLabel =
              incident.reportedAgeLabel ?? formatRelativeAge(incident.reportedAt);

            return (
              <li key={incident.publicUuid}>
                <label
                  className={`flex items-start gap-2 rounded-xl border p-2.5 ${getSeverityCardAccent(incident.severity)} ${getDispatcherSelectableRowClasses({ selected, variant: "card" })}`}
                >
                  <input
                    type="radio"
                    name="gateway-active-incident"
                    value={incident.publicUuid}
                    checked={selected}
                    onChange={() => onSelect(incident.publicUuid)}
                    className="mt-1 shrink-0"
                  />
                  <span className="min-w-0 flex-1">
                    <span className="flex flex-wrap items-center gap-2">
                      <Badge tone={getSeverityBadgeTone(incident.severity)}>
                        {formatBadgeLabel(incident.severity)}
                      </Badge>
                      <span className="inline-flex max-w-full items-center rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-700 ring-1 ring-slate-200">
                        {incident.categoryLabel}
                      </span>
                      <Badge tone={incident.status}>
                        {formatIncidentStatus(incident.status)}
                      </Badge>
                      <span className="text-xs text-slate-500">
                        Reported {reportedAgeLabel}
                      </span>
                    </span>
                    <span className="mt-1 block text-sm font-semibold text-slate-900">
                      {incident.title}
                    </span>
                    <span className="mt-0.5 block font-mono text-xs text-slate-500">
                      {incident.incidentCode}
                    </span>
                    <span className="mt-1 flex items-center gap-1 text-xs text-slate-500">
                      <MapPin
                        className="h-3.5 w-3.5 shrink-0 text-slate-400"
                        aria-hidden
                      />
                      <span className="min-w-0 truncate">{incident.locationText}</span>
                    </span>
                  </span>
                </label>
              </li>
            );
          })}
        </ul>
      )}
    </fieldset>
  );
}
