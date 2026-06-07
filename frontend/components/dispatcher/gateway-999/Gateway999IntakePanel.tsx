"use client";

import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import { Gateway999IncidentPicker } from "@/components/dispatcher/gateway-999/Gateway999IncidentPicker";
import type {
  Gateway999FormState,
  Gateway999IncidentOption,
  Gateway999SubmitLabel,
} from "@/components/dispatcher/gateway-999/types";
import { RouteSelector } from "@/components/dispatcher/triage/RouteSelector";
import {
  triageFieldClassName,
  triageLabelClassName,
} from "@/components/dispatcher/triage/triageFormStyles";
import type { RouteMode } from "@/components/dispatcher/triage/types";
import { DisasterLinkSelector } from "@/components/dispatcher/disasters/DisasterLinkSelector";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { Button } from "@/components/ui/Button";
import { INCIDENT_CATEGORY_OPTIONS } from "@/lib/incident-category-options";

const SEVERITY_OPTIONS = [
  { value: "low", label: "Low" },
  { value: "medium", label: "Medium" },
  { value: "high", label: "High" },
  { value: "critical", label: "Critical" },
] as const;

const PRIORITY_OPTIONS = [
  { value: "low", label: "Low" },
  { value: "medium", label: "Medium" },
  { value: "high", label: "High" },
  { value: "urgent", label: "Urgent" },
] as const;

const secondaryLabelClassName = "block text-xs font-medium text-slate-500";

function FieldError({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <p className="mt-1 text-xs text-red-600" role="alert">
      {message}
    </p>
  );
}

type Gateway999IntakePanelProps = {
  form: Gateway999FormState;
  routeMode: RouteMode;
  isSubmitting: boolean;
  submitError: string;
  showValidation: boolean;
  canSubmit: boolean;
  submitLabel: Gateway999SubmitLabel;
  incidents: Gateway999IncidentOption[];
  incidentsLoading: boolean;
  incidentsError: string | null;
  onFormChange: (patch: Partial<Gateway999FormState>) => void;
  onSelectRoute: (
    mode: "service_case" | "emergency_incident" | "existing_incident",
  ) => void;
  onRetryIncidents: () => void;
  onCancel: () => void;
  selectedDisasterPublicUuid?: string | null;
  onDisasterChange?: (uuid: string | null) => void;
};

export function Gateway999IntakePanel({
  form,
  routeMode,
  isSubmitting,
  submitError,
  showValidation,
  canSubmit,
  submitLabel,
  incidents,
  incidentsLoading,
  incidentsError,
  onFormChange,
  onSelectRoute,
  onRetryIncidents,
  onCancel,
  selectedDisasterPublicUuid = null,
  onDisasterChange,
}: Gateway999IntakePanelProps) {
  const categoryError =
    showValidation && !form.categoryCode.trim() ? "Choose a category." : null;
  const summaryError =
    showValidation && !form.summary.trim() ? "Add a summary for this call." : null;
  const severityError =
    showValidation &&
    routeMode === "emergency_incident" &&
    !form.severityCode
      ? "Choose a severity level."
      : null;
  const incidentError =
    showValidation &&
    routeMode === "existing_incident" &&
    !form.incidentPublicUuid
      ? "Select an active incident."
      : null;

  return (
    <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-2xl border border-slate-200/90 bg-white shadow-sm">
      <div className="shrink-0 border-b border-slate-100 px-4 py-3">
        <h2 className="text-sm font-semibold text-slate-900">Call Intake & Routing</h2>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto px-4 py-3">
        <div className="space-y-4">
          <section aria-labelledby="gateway-call-details">
            <h3
              id="gateway-call-details"
              className="text-xs font-semibold uppercase tracking-wide text-slate-500"
            >
              Call Details
            </h3>
            <div className="mt-2 grid gap-2.5 sm:grid-cols-2">
              <div>
                <FieldLabel htmlFor="caller-phone">Caller Phone Number</FieldLabel>
                <input
                  id="caller-phone"
                  type="tel"
                  value={form.callerPhoneNumber}
                  onChange={(event) =>
                    onFormChange({ callerPhoneNumber: event.target.value })
                  }
                  disabled={isSubmitting}
                  className={triageFieldClassName}
                  placeholder="Optional"
                />
              </div>
              <div>
                <FieldLabel htmlFor="call-started-at">Call Started At</FieldLabel>
                <input
                  id="call-started-at"
                  type="datetime-local"
                  value={form.callStartedAt}
                  onChange={(event) =>
                    onFormChange({ callStartedAt: event.target.value })
                  }
                  disabled={isSubmitting}
                  className={triageFieldClassName}
                />
              </div>
              <div className="sm:col-span-2">
                <label className={secondaryLabelClassName} htmlFor="reported-at">
                  Reported At
                </label>
                <input
                  id="reported-at"
                  type="datetime-local"
                  value={form.reportedAt}
                  onChange={(event) =>
                    onFormChange({ reportedAt: event.target.value })
                  }
                  disabled={isSubmitting}
                  className={`${triageFieldClassName} text-slate-700`}
                />
              </div>
            </div>
          </section>

          <section aria-labelledby="gateway-report-details">
            <h3
              id="gateway-report-details"
              className="text-xs font-semibold uppercase tracking-wide text-slate-500"
            >
              Report Details
            </h3>
            <div className="mt-2 space-y-2.5">
              <div>
                <FieldLabel
                  htmlFor="gateway-category"
                  required
                >
                  Category
                </FieldLabel>
                <select
                  id="gateway-category"
                  value={form.categoryCode}
                  required
                  onChange={(event) =>
                    onFormChange({ categoryCode: event.target.value })
                  }
                  disabled={isSubmitting}
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
                <FieldLabel htmlFor="gateway-summary" required>
                  Summary
                </FieldLabel>
                <input
                  id="gateway-summary"
                  type="text"
                  value={form.summary}
                  required
                  maxLength={255}
                  onChange={(event) => onFormChange({ summary: event.target.value })}
                  disabled={isSubmitting}
                  className={triageFieldClassName}
                  placeholder="Brief description of the emergency call"
                  aria-invalid={summaryError ? true : undefined}
                />
                <FieldError message={summaryError} />
              </div>

              <div>
                <FieldLabel htmlFor="gateway-description">
                  Description / Call Notes
                </FieldLabel>
                <textarea
                  id="gateway-description"
                  value={form.description}
                  onChange={(event) =>
                    onFormChange({ description: event.target.value })
                  }
                  disabled={isSubmitting}
                  rows={3}
                  className={`${triageFieldClassName} min-h-[72px] resize-y`}
                  placeholder="Optional notes from the live call"
                />
              </div>
            </div>
          </section>

          <section aria-labelledby="gateway-route">
            <RouteSelector
              routeMode={routeMode}
              onSelect={onSelectRoute}
              disabled={isSubmitting}
              title="Route This Call"
              subtitle="Choose where this live call should be routed."
              required
            />

            {routeMode === "emergency_incident" ? (
              <div className="mt-3 space-y-2.5 rounded-lg border border-slate-100 bg-slate-50/40 p-3">
                <div>
                  <FieldLabel htmlFor="gateway-severity" required>
                    Severity
                  </FieldLabel>
                  <select
                    id="gateway-severity"
                    value={form.severityCode}
                    required
                    onChange={(event) =>
                      onFormChange({
                        severityCode: event.target.value as Gateway999FormState["severityCode"],
                      })
                    }
                    disabled={isSubmitting}
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

                <div>
                  <FieldLabel htmlFor="gateway-incident-title">
                    Incident Title Override
                  </FieldLabel>
                  <input
                    id="gateway-incident-title"
                    type="text"
                    value={form.incidentTitle}
                    onChange={(event) =>
                      onFormChange({ incidentTitle: event.target.value })
                    }
                    disabled={isSubmitting}
                    className={triageFieldClassName}
                    placeholder="Optional"
                  />
                </div>

                <div>
                  <FieldLabel htmlFor="gateway-incident-description">
                    Incident Description Override
                  </FieldLabel>
                  <textarea
                    id="gateway-incident-description"
                    value={form.incidentDescription}
                    onChange={(event) =>
                      onFormChange({ incidentDescription: event.target.value })
                    }
                    disabled={isSubmitting}
                    rows={2}
                    className={triageFieldClassName}
                    placeholder="Optional"
                  />
                </div>
              </div>
            ) : null}

            {routeMode === "existing_incident" ? (
              <div className="mt-3 space-y-2.5 rounded-lg border border-slate-100 bg-slate-50/40 p-3">
                <Gateway999IncidentPicker
                  incidents={incidents}
                  selectedUuid={form.incidentPublicUuid}
                  isLoading={incidentsLoading}
                  error={incidentsError}
                  disabled={isSubmitting}
                  onSelect={(publicUuid) =>
                    onFormChange({ incidentPublicUuid: publicUuid })
                  }
                  onRetry={onRetryIncidents}
                />
                <FieldError message={incidentError} />

                <div>
                  <FieldLabel htmlFor="gateway-link-type">Link Type</FieldLabel>
                  <select
                    id="gateway-link-type"
                    value={form.linkType}
                    onChange={(event) =>
                      onFormChange({
                        linkType: event.target.value as Gateway999FormState["linkType"],
                      })
                    }
                    disabled={isSubmitting}
                    className={triageFieldClassName}
                  >
                    <option value="supporting_report">Supporting Report</option>
                    <option value="follow_up_report">Follow-up Report</option>
                  </select>
                </div>

                <div>
                  <FieldLabel htmlFor="gateway-link-note">Link Note</FieldLabel>
                  <textarea
                    id="gateway-link-note"
                    value={form.linkNote}
                    maxLength={500}
                    onChange={(event) => onFormChange({ linkNote: event.target.value })}
                    disabled={isSubmitting}
                    rows={2}
                    className={triageFieldClassName}
                    placeholder="Optional context for why this call belongs to the selected incident."
                  />
                  <p className="mt-1 text-xs text-slate-500">
                    Optional context for why this call belongs to the selected incident.
                  </p>
                </div>
              </div>
            ) : null}

            {(routeMode === "emergency_incident" ||
              routeMode === "existing_incident") &&
            onDisasterChange ? (
              <DisasterLinkSelector
                selectedDisasterPublicUuid={selectedDisasterPublicUuid}
                onChange={onDisasterChange}
                disabled={isSubmitting}
                className="mt-3"
              />
            ) : null}

            {routeMode === "service_case" ? (
              <div className="mt-3 rounded-lg border border-slate-100 bg-slate-50/40 p-3">
                <FieldLabel htmlFor="gateway-priority">Priority</FieldLabel>
                <select
                  id="gateway-priority"
                  value={form.priorityLevel}
                  onChange={(event) =>
                    onFormChange({
                      priorityLevel: event.target.value as Gateway999FormState["priorityLevel"],
                    })
                  }
                  disabled={isSubmitting}
                  className={triageFieldClassName}
                >
                  <option value="">— Optional —</option>
                  {PRIORITY_OPTIONS.map((option) => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
            ) : null}
          </section>

          {submitError ? <ErrorAlert message={submitError} /> : null}
        </div>
      </div>

      <div className="shrink-0 flex flex-col-reverse gap-3 border-t border-slate-100 px-4 py-3 sm:flex-row sm:justify-end">
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
          {isSubmitting ? "Submitting…" : submitLabel}
        </Button>
      </div>
    </div>
  );
}
