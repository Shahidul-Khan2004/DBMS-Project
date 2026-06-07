import { triageFieldClassName } from "@/components/dispatcher/triage/triageFormStyles";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import type { DismissDraft } from "@/components/dispatcher/triage/types";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";

interface DismissRouteFormProps {
  disposition: "duplicate" | "false_report";
  draft: DismissDraft;
  onChange: (draft: DismissDraft) => void;
  onSubmit: () => void;
  submitError?: string | null;
  isSubmitting?: boolean;
}

const DISMISS_COPY = {
  duplicate: {
    title: "Mark as Duplicate",
    description:
      "Close this report as a duplicate of an existing intake. No case or incident will be created.",
    submitLabel: "Mark as Duplicate",
    submittingLabel: "Marking Duplicate...",
  },
  false_report: {
    title: "Mark as False Report",
    description:
      "Close this report as a false or invalid submission. No case or incident will be created.",
    submitLabel: "Mark as False Report",
    submittingLabel: "Marking False Report...",
  },
} as const;

export function DismissRouteForm({
  disposition,
  draft,
  onChange,
  onSubmit,
  submitError = null,
  isSubmitting = false,
}: DismissRouteFormProps) {
  const copy = DISMISS_COPY[disposition];

  return (
    <div className="space-y-3">
      <header>
        <h4 className="text-sm font-semibold text-slate-900">{copy.title}</h4>
        <p className="mt-0.5 text-xs text-slate-600">{copy.description}</p>
      </header>

      <div>
        <FieldLabel htmlFor="dismiss-note">Dispatcher Note</FieldLabel>
        <textarea
          id="dismiss-note"
          value={draft.note}
          onChange={(event) => onChange({ note: event.target.value })}
          rows={2}
          placeholder="Optional note for audit trail..."
          className={triageFieldClassName}
        />
      </div>

      {submitError ? <ErrorAlert message={submitError} /> : null}

      <div className="flex flex-wrap items-center justify-end gap-2 border-t border-slate-200/80 pt-3">
        <Button
          type="button"
          variant="primary"
          size="sm"
          onClick={onSubmit}
          disabled={isSubmitting}
          isLoading={isSubmitting}
        >
          {isSubmitting ? copy.submittingLabel : copy.submitLabel}
        </Button>
      </div>
    </div>
  );
}
