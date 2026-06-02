"use client";

import type { FormEvent } from "react";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import {
  triageFieldClassName,
} from "@/components/dispatcher/triage/triageFormStyles";
import { Button } from "@/components/ui/Button";
import { INCIDENT_CATEGORY_OPTIONS } from "@/lib/incident-category-options";

const SEVERITY_OPTIONS = [
  { value: "low", label: "Low" },
  { value: "medium", label: "Medium" },
  { value: "high", label: "High" },
  { value: "critical", label: "Critical" },
] as const;

export type SeverityCode = (typeof SEVERITY_OPTIONS)[number]["value"];

type CreateStandaloneIncidentDetailsPanelProps = {
  categoryCode: string;
  severityCode: SeverityCode | "";
  reportedAt: string;
  title: string;
  description: string;
  isSubmitting: boolean;
  canSubmit: boolean;
  showValidation: boolean;
  onCategoryChange: (value: string) => void;
  onSeverityChange: (value: SeverityCode) => void;
  onReportedAtChange: (value: string) => void;
  onTitleChange: (value: string) => void;
  onDescriptionChange: (value: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onCancel: () => void;
};

function FieldError({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <p className="mt-1 text-xs text-red-600" role="alert">
      {message}
    </p>
  );
}

export function CreateStandaloneIncidentDetailsPanel({
  categoryCode,
  severityCode,
  reportedAt,
  title,
  description,
  isSubmitting,
  canSubmit,
  showValidation,
  onCategoryChange,
  onSeverityChange,
  onReportedAtChange,
  onTitleChange,
  onDescriptionChange,
  onSubmit,
  onCancel,
}: CreateStandaloneIncidentDetailsPanelProps) {
  const categoryError =
    showValidation && !categoryCode.trim() ? "Choose a category." : null;
  const severityError =
    showValidation && !severityCode ? "Choose a severity level." : null;
  const titleError =
    showValidation && !title.trim() ? "Add a title." : null;

  return (
    <CommandSectionCard
      title="Incident Details"
      subtitle="Record the emergency classification and verified summary."
      className="h-full p-4 sm:p-4"
      bodyClassName="mt-2 lg:mt-2"
      fillHeight
    >
      <form onSubmit={onSubmit} noValidate>
        <div className="space-y-2.5">
          <div className="grid gap-2.5 sm:grid-cols-2 lg:grid-cols-3">
            <div>
              <FieldLabel htmlFor="category" required>
                Category
              </FieldLabel>
              <select
                id="category"
                value={categoryCode}
                required
                onChange={(event) => onCategoryChange(event.target.value)}
                className={triageFieldClassName}
                aria-invalid={categoryError ? true : undefined}
              >
                <option value="" disabled>
                  Select category
                </option>
                {INCIDENT_CATEGORY_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              <FieldError message={categoryError} />
            </div>

            <div>
              <FieldLabel htmlFor="severity" required>
                Severity
              </FieldLabel>
              <select
                id="severity"
                value={severityCode}
                required
                onChange={(event) =>
                  onSeverityChange(event.target.value as SeverityCode)
                }
                className={triageFieldClassName}
                aria-invalid={severityError ? true : undefined}
              >
                <option value="" disabled>
                  Select severity
                </option>
                {SEVERITY_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
              <FieldError message={severityError} />
            </div>

            <div className="sm:col-span-2 lg:col-span-1">
              <FieldLabel htmlFor="reported-at">Reported At</FieldLabel>
              <input
                id="reported-at"
                type="datetime-local"
                value={reportedAt}
                onChange={(event) => onReportedAtChange(event.target.value)}
                className={triageFieldClassName}
              />
            </div>
          </div>

          <div>
            <FieldLabel htmlFor="title" required>
              Title
            </FieldLabel>
            <input
              id="title"
              type="text"
              value={title}
              required
              onChange={(event) => onTitleChange(event.target.value)}
              className={triageFieldClassName}
              placeholder="Worker collapsed near loading dock"
              aria-invalid={titleError ? true : undefined}
            />
            <FieldError message={titleError} />
          </div>

          <div>
            <FieldLabel htmlFor="description">Description</FieldLabel>
            <textarea
              id="description"
              value={description}
              onChange={(event) => onDescriptionChange(event.target.value)}
              rows={3}
              className={`${triageFieldClassName} min-h-[90px] max-h-[120px] resize-none`}
              placeholder="On-site medic requested immediate ambulance dispatch."
            />
          </div>
        </div>

        <div className="mt-3 flex shrink-0 flex-col-reverse gap-3 border-t border-slate-100 pt-3 sm:flex-row sm:justify-end">
          <Button
            type="button"
            variant="secondary"
            className="w-full sm:w-auto"
            disabled={isSubmitting}
            onClick={onCancel}
          >
            Cancel
          </Button>
          <Button
            type="submit"
            variant="primary"
            className="w-full sm:w-auto"
            isLoading={isSubmitting}
            disabled={!canSubmit}
          >
            {isSubmitting ? "Creating Incident…" : "Create Incident"}
          </Button>
        </div>
      </form>
    </CommandSectionCard>
  );
}
