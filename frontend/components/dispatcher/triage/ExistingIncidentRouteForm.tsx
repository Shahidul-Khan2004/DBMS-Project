import { FieldLabel, FieldLegend } from "@/components/dispatcher/FieldLabel";
import { getDispatcherSelectableRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import { ReportedLocationDisplay } from "@/components/dispatcher/triage/ReportedLocationDisplay";
import {
  triageFieldClassName,
} from "@/components/dispatcher/triage/triageFormStyles";
import type {
  ActiveIncidentOption,
  IntakeLocation,
  LinkDraft,
} from "@/components/dispatcher/triage/types";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";

interface ExistingIncidentRouteFormProps {
  intakeLocation: IntakeLocation;
  draft: LinkDraft;
  incidents: ActiveIncidentOption[];
  incidentsLoading?: boolean;
  incidentsError?: string | null;
  onRetryIncidents?: () => void;
  onChange: (draft: LinkDraft) => void;
  onBack: () => void;
  onSubmit: () => void;
  submitError?: string | null;
  isSubmitting?: boolean;
  submitDisabled?: boolean;
}

function formatIncidentSubtitle(incident: ActiveIncidentOption): string {
  const parts: string[] = [];

  if (incident.categoryLabel) {
    parts.push(incident.categoryLabel);
  }
  if (incident.severityLabel) {
    parts.push(incident.severityLabel);
  }
  parts.push(incident.statusLabel);
  if (incident.reportedAgeLabel) {
    parts.push(`Reported ${incident.reportedAgeLabel}`);
  }
  if (incident.locationText && incident.locationText !== "Location unavailable") {
    parts.push(incident.locationText);
  }

  return parts.join(" · ");
}

export function ExistingIncidentRouteForm({
  intakeLocation,
  draft,
  incidents,
  incidentsLoading = false,
  incidentsError = null,
  onRetryIncidents,
  onChange,
  onBack,
  onSubmit,
  submitError = null,
  isSubmitting = false,
  submitDisabled = false,
}: ExistingIncidentRouteFormProps) {
  const disabled =
    isSubmitting || submitDisabled || !draft.incidentId || incidentsLoading;

  return (
    <div className="space-y-3">
      <header>
        <h4 className="text-sm font-semibold text-slate-900">
          Link to Existing Active Incident
        </h4>
        <p className="mt-0.5 text-xs text-slate-600">
          Attach this report to an incident already being handled.
        </p>
      </header>

      <ReportedLocationDisplay
        compact
        location={intakeLocation}
        label="Selected Intake Location"
        showViewHistory={false}
      />

      <fieldset>
        <FieldLegend required>Selected Incident</FieldLegend>        {incidentsLoading ? (
          <div className="mt-1.5">
            <LoadingSkeleton lines={2} />
          </div>
        ) : incidentsError ? (
          <div className="mt-1.5 space-y-2">
            <ErrorAlert message={incidentsError} />
            {onRetryIncidents ? (
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={onRetryIncidents}
              >
                Retry
              </Button>
            ) : null}
          </div>
        ) : incidents.length === 0 ? (
          <p className="mt-1.5 text-sm text-slate-600">
            No active incidents are available to link.
          </p>
        ) : (
          <ul className="mt-1.5 space-y-1.5">
            {incidents.map((incident) => {
              const selected = draft.incidentId === incident.id;
              return (
                <li key={incident.id}>
                  <label
                    className={`flex items-start gap-2 rounded-lg border p-2 ${getDispatcherSelectableRowClasses({ selected, variant: "flat" })}`}
                  >
                    <input
                      type="radio"
                      name="active-incident"
                      value={incident.id}
                      checked={selected}
                      onChange={() =>
                        onChange({ ...draft, incidentId: incident.id })
                      }
                      className="mt-0.5 shrink-0"
                    />
                    <span className="min-w-0 text-sm">
                      <span className="font-medium text-slate-900">
                        {incident.incidentCode} · {incident.title}
                      </span>
                      <span className="mt-0.5 block text-xs leading-snug text-slate-600">
                        {formatIncidentSubtitle(incident)}
                      </span>
                    </span>
                  </label>
                </li>
              );
            })}
          </ul>
        )}
      </fieldset>

      <div>
        <FieldLabel htmlFor="link-note">Optional Note</FieldLabel>        <textarea
          id="link-note"
          value={draft.note}
          maxLength={500}
          onChange={(event) => onChange({ ...draft, note: event.target.value })}
          rows={2}
          placeholder="Add context from this report..."
          className={triageFieldClassName}
        />
      </div>

      {submitError ? <ErrorAlert message={submitError} /> : null}

      <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-200/80 pt-3">
        <Button type="button" variant="secondary" size="sm" onClick={onBack}>
          Back to Route Options
        </Button>
        <Button
          type="button"
          variant="primary"
          size="sm"
          onClick={onSubmit}
          disabled={disabled}
          isLoading={isSubmitting}
        >
          {isSubmitting ? "Linking Report..." : "Link Report"}
        </Button>
      </div>
    </div>
  );
}
