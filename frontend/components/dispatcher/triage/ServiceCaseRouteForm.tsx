import {
  triageFieldClassName,
} from "@/components/dispatcher/triage/triageFormStyles";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import type { ServiceCaseDraft } from "@/components/dispatcher/triage/types";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";

interface ServiceCaseRouteFormProps {
  draft: ServiceCaseDraft;
  onChange: (draft: ServiceCaseDraft) => void;
  onBack: () => void;
  onSubmit: () => void;
  submitError?: string | null;
  isSubmitting?: boolean;
  submitDisabled?: boolean;
}

export function ServiceCaseRouteForm({
  draft,
  onChange,
  onBack,
  onSubmit,
  submitError = null,
  isSubmitting = false,
  submitDisabled = false,
}: ServiceCaseRouteFormProps) {
  const disabled = isSubmitting || submitDisabled;

  return (
    <div className="space-y-3">
      <header>
        <h4 className="text-sm font-semibold text-slate-900">Create Service Case</h4>
        <p className="mt-0.5 text-xs text-slate-600">
          Create a non-emergency case from this intake report.
        </p>
      </header>

      <div className="grid gap-3 lg:grid-cols-2">
        <div className="lg:col-span-2">
          <FieldLabel htmlFor="case-title">Case Title</FieldLabel>
          <input
            id="case-title"
            value={draft.title}
            onChange={(event) =>
              onChange({ ...draft, title: event.target.value })
            }
            className={triageFieldClassName}
          />
        </div>

        <div>
          <FieldLabel htmlFor="case-priority">Priority Level</FieldLabel>
          <select
            id="case-priority"
            value={draft.priority}
            onChange={(event) =>
              onChange({
                ...draft,
                priority: event.target.value as ServiceCaseDraft["priority"],
              })
            }
            className={triageFieldClassName}
          >
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
            <option value="urgent">Urgent</option>
          </select>
        </div>
      </div>

      <div>
        <FieldLabel htmlFor="case-description">Case Description</FieldLabel>
        <textarea
          id="case-description"
          value={draft.description}
          onChange={(event) =>
            onChange({ ...draft, description: event.target.value })
          }
          rows={2}
          placeholder="Add handling details for this case..."
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
          {isSubmitting ? "Creating Case..." : "Create Service Case"}
        </Button>
      </div>
    </div>
  );
}
