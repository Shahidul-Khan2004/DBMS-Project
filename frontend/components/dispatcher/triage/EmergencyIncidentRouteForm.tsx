import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { ReportedLocationDisplay } from "@/components/dispatcher/triage/ReportedLocationDisplay";
import {
  triageFieldClassName,
} from "@/components/dispatcher/triage/triageFormStyles";import type { EmergencyDraft, IntakeQueueItem } from "@/components/dispatcher/triage/types";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";

interface EmergencyIncidentRouteFormProps {
  item: IntakeQueueItem;
  draft: EmergencyDraft;
  onChange: (draft: EmergencyDraft) => void;
  onBack: () => void;
  onSubmit: () => void;
  onEditReportedLocation: () => void;
  submitError?: string | null;
  isSubmitting?: boolean;
  submitDisabled?: boolean;
}

export function EmergencyIncidentRouteForm({
  item,
  draft,
  onChange,
  onBack,
  onSubmit,
  onEditReportedLocation,
  submitError = null,
  isSubmitting = false,
  submitDisabled = false,
}: EmergencyIncidentRouteFormProps) {
  const disabled = isSubmitting || submitDisabled;

  return (
    <div className="space-y-3">
      <header>
        <h4 className="text-sm font-semibold text-slate-900">
          Create Emergency Incident
        </h4>
        <p className="mt-0.5 text-xs text-slate-600">
          Create a new emergency incident from this intake report.
        </p>
      </header>

      <div className="rounded-lg border border-slate-100 bg-slate-50/60 p-2.5">
        <ReportedLocationDisplay
          compact
          location={item.location}
          label="Incident Location"
          supportingText="Using reported location for the new incident."
          editLabel="Edit Reported Location"
          showViewHistory={false}
          previewKey={item.id}
          onEditLocation={onEditReportedLocation}
        />
      </div>

      {submitDisabled ? (
        <div className="rounded-lg border border-amber-200 bg-amber-50/80 px-3 py-2 text-sm text-amber-950">
          <p>
            A reported location is required before creating an emergency incident.
          </p>
          <Button
            type="button"
            variant="primary"
            size="sm"
            className="mt-1.5"
            onClick={onEditReportedLocation}
          >
            Edit Reported Location
          </Button>
        </div>
      ) : null}

      <div className="grid gap-3 lg:grid-cols-2">
        <div>
          <FieldLabel htmlFor="incident-severity" required>
            Severity
          </FieldLabel>          <select
            id="incident-severity"
            value={draft.severity}
            required
            onChange={(event) =>
              onChange({
                ...draft,
                severity: event.target.value as EmergencyDraft["severity"],
              })
            }
            className={triageFieldClassName}
          >
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="critical">Critical</option>
          </select>
        </div>

        <div>
          <FieldLabel htmlFor="incident-title">Incident Title</FieldLabel>          <input
            id="incident-title"
            value={draft.title}
            onChange={(event) =>
              onChange({ ...draft, title: event.target.value })
            }
            className={triageFieldClassName}
          />
        </div>
      </div>

      <div>
        <FieldLabel htmlFor="incident-description">Incident Description</FieldLabel>        <textarea
          id="incident-description"
          value={draft.description}
          onChange={(event) =>
            onChange({ ...draft, description: event.target.value })
          }
          rows={2}
          placeholder="Add official operational incident details..."
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
          {isSubmitting ? "Creating Incident..." : "Create Emergency Incident"}
        </Button>
      </div>
    </div>
  );
}
