"use client";

import { useCallback, useEffect, useMemo, useState, type MouseEvent } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";
import { toast } from "sonner";
import { getDispatcherSelectableRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import { getIntakeStatusLabel } from "@/components/dispatcher/triage/intakeStatus";
import { FieldLabel } from "@/components/dispatcher/FieldLabel";
import {
  triageFieldClassName,
} from "@/components/dispatcher/triage/triageFormStyles";
import { formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { formatIntakeAgeLabel } from "@/lib/format-relative-age";
import { mapLinkReportToIncidentError } from "@/lib/incident-command-api-errors";
import {
  fetchAllPendingIntakeReports,
  linkIntakeToIncident,
} from "@/lib/operations-intake-triage";
import type { LinkIntakeToIncidentPayload } from "@/lib/operations-intake-triage";
import type { OperationsIntakeReport } from "@/types/operations-intake";

const LINK_NOTE_MAX_LENGTH = 500;
const CANDIDATE_LIST_LIMIT = 100;

type LinkType = LinkIntakeToIncidentPayload["linkType"];

type SelectedLinkConfig = {
  report: OperationsIntakeReport;
  linkType: LinkType;
  note: string;
};

function formatCandidateLocation(report: OperationsIntakeReport): string | null {
  const loc = report.location;
  if (!loc) return null;
  return loc.address_text?.trim() || loc.place_name?.trim() || null;
}

function matchesSearch(report: OperationsIntakeReport, query: string): boolean {
  const normalized = query.trim().toLowerCase();
  if (!normalized) return true;

  const locationText = formatCandidateLocation(report);
  const haystack = [
    report.report_code,
    report.summary,
    report.category_code,
    locationText,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  return haystack.includes(normalized);
}

function createDefaultSelection(report: OperationsIntakeReport): SelectedLinkConfig {
  return {
    report,
    linkType: "supporting_report",
    note: "",
  };
}

function CandidateRow({
  report,
  selected,
  disabled,
  onToggle,
}: {
  report: OperationsIntakeReport;
  selected: boolean;
  disabled: boolean;
  onToggle: () => void;
}) {
  const locationPreview = formatCandidateLocation(report);
  const statusLabel = getIntakeStatusLabel(
    report.intake_status as "received" | "under_review",
  );
  const ageLabel = formatIntakeAgeLabel(
    report.intake_status,
    report.reported_at,
    report.updated_at,
  );
  const checkboxId = `link-candidate-${report.public_uuid}`;

  return (
    <div
      role="button"
      tabIndex={disabled ? -1 : 0}
      onClick={(event: MouseEvent<HTMLDivElement>) => {
        if (disabled) return;
        if (event.metaKey || event.ctrlKey) {
          event.preventDefault();
        }
        onToggle();
      }}
      onKeyDown={(event) => {
        if (disabled) return;
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          onToggle();
        }
      }}
      className={`flex w-full gap-3 rounded-lg border px-3 py-2.5 text-left ${getDispatcherSelectableRowClasses({
        selected,
        disabled,
        variant: "flat",
      })}`}
    >
      <input
        id={checkboxId}
        type="checkbox"
        checked={selected}
        disabled={disabled}
        onChange={(event) => {
          event.stopPropagation();
          if (!disabled) onToggle();
        }}
        onClick={(event) => event.stopPropagation()}
        className="mt-0.5 h-4 w-4 shrink-0 rounded border-slate-300 text-[#002D62] focus:ring-[#002D62]"
        aria-label={`Select ${report.report_code}`}
      />
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold text-slate-900">
          {report.summary?.trim() || "Untitled report"}
        </p>
        <p className="mt-0.5 font-mono text-xs text-slate-500">{report.report_code}</p>
        <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
          <span className="text-xs text-slate-600">
            {formatBadgeLabel(report.category_code)}
          </span>
          <span className="text-slate-300" aria-hidden>
            ·
          </span>
          <span className="inline-flex items-center rounded-full bg-slate-100 px-2 py-0.5 text-[11px] font-semibold text-slate-700 ring-1 ring-slate-200">
            {statusLabel}
          </span>
          <span className="text-slate-300" aria-hidden>
            ·
          </span>
          <span className="text-xs text-slate-500">Reported {ageLabel}</span>
        </div>
        {locationPreview ? (
          <p className="mt-1 text-xs text-slate-500">{locationPreview}</p>
        ) : null}
      </div>
    </div>
  );
}

function SelectedReportConfigRow({
  config,
  error,
  disabled,
  onRemove,
  onLinkTypeChange,
  onNoteChange,
}: {
  config: SelectedLinkConfig;
  error?: string;
  disabled: boolean;
  onRemove: () => void;
  onLinkTypeChange: (linkType: LinkType) => void;
  onNoteChange: (note: string) => void;
}) {
  const { report } = config;

  return (
    <div className="space-y-2 rounded-lg border border-slate-200 bg-white p-3">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <p className="text-sm font-semibold text-slate-900">
            {report.summary?.trim() || "Untitled report"}
          </p>
          <p className="font-mono text-xs text-slate-500">{report.report_code}</p>
        </div>
        <button
          type="button"
          onClick={onRemove}
          disabled={disabled}
          className="shrink-0 rounded p-1 text-slate-400 transition hover:bg-slate-100 hover:text-slate-700 disabled:cursor-not-allowed disabled:opacity-50"
          aria-label={`Remove ${report.report_code} from selection`}
        >
          <X className="h-4 w-4" aria-hidden />
        </button>
      </div>

      <FieldLabel htmlFor={`link-type-${report.public_uuid}`}>Link Type</FieldLabel>
        <select
          id={`link-type-${report.public_uuid}`}
          value={config.linkType}
          onChange={(event) => onLinkTypeChange(event.target.value as LinkType)}
          className={triageFieldClassName}
          disabled={disabled}
        >
          <option value="supporting_report">Supporting Report</option>
          <option value="follow_up_report">Follow-up Report</option>
        </select>

      <FieldLabel htmlFor={`link-note-${report.public_uuid}`}>Link Note</FieldLabel>
        <textarea
          id={`link-note-${report.public_uuid}`}
          value={config.note}
          onChange={(event) => onNoteChange(event.target.value)}
          placeholder="Optional relationship note"
          rows={2}
          maxLength={LINK_NOTE_MAX_LENGTH}
          className={triageFieldClassName}
          disabled={disabled}
        />
        <p className="mt-1 text-xs text-slate-500">
          {config.note.length}/{LINK_NOTE_MAX_LENGTH}
        </p>

      {error ? (
        <p className="text-xs text-[#991B1B]" role="alert">
          {error}
        </p>
      ) : null}
    </div>
  );
}

type LinkReportToIncidentDialogProps = {
  open: boolean;
  incidentPublicUuid: string;
  incidentTitle: string;
  linkedReportUuids: string[];
  onClose: () => void;
  onSuccess: () => Promise<void>;
};

export function LinkReportToIncidentDialog({
  open,
  incidentPublicUuid,
  incidentTitle,
  linkedReportUuids,
  onClose,
  onSuccess,
}: LinkReportToIncidentDialogProps) {
  const [candidates, setCandidates] = useState<OperationsIntakeReport[]>([]);
  const [isLoadingCandidates, setIsLoadingCandidates] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [selection, setSelection] = useState<Map<string, SelectedLinkConfig>>(
    () => new Map(),
  );
  const [perReportErrors, setPerReportErrors] = useState<Map<string, string>>(
    () => new Map(),
  );
  const [batchError, setBatchError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const linkedUuidSet = useMemo(
    () => new Set(linkedReportUuids.filter(Boolean)),
    [linkedReportUuids],
  );

  const loadCandidates = useCallback(async () => {
    setIsLoadingCandidates(true);
    setLoadError(null);

    try {
      const reports = await fetchAllPendingIntakeReports({
        statusFilter: "all",
        categoryFilter: "all",
        sortOrder: "newest",
        limit: CANDIDATE_LIST_LIMIT,
        offset: 0,
      });

      const eligible = reports.filter(
        (report) =>
          !report.has_incident && !linkedUuidSet.has(report.public_uuid),
      );

      setCandidates(eligible);
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Failed to load link report candidates", err);
      }
      setLoadError("Unable to load available reports.");
      setCandidates([]);
    } finally {
      setIsLoadingCandidates(false);
    }
  }, [linkedUuidSet]);

  const resetFormState = useCallback(() => {
    setSearchQuery("");
    setSelection(new Map());
    setPerReportErrors(new Map());
    setBatchError(null);
  }, []);

  useEffect(() => {
    if (!open) return;
    resetFormState();
    void loadCandidates();
  }, [open, loadCandidates, resetFormState]);

  const filteredCandidates = useMemo(
    () => candidates.filter((report) => matchesSearch(report, searchQuery)),
    [candidates, searchQuery],
  );

  const selectedCount = selection.size;
  const selectedEntries = useMemo(
    () => Array.from(selection.entries()),
    [selection],
  );

  const hasNoteLengthViolation = useMemo(
    () => selectedEntries.some(([, cfg]) => cfg.note.length > LINK_NOTE_MAX_LENGTH),
    [selectedEntries],
  );

  const toggleSelection = useCallback((report: OperationsIntakeReport) => {
      setSelection((prev) => {
        const next = new Map(prev);
        const uuid = report.public_uuid;

        if (next.has(uuid)) {
          next.delete(uuid);
        } else {
          next.set(uuid, createDefaultSelection(report));
        }

        return next;
      });
      setPerReportErrors((prev) => {
        if (!prev.has(report.public_uuid)) return prev;
        const next = new Map(prev);
        next.delete(report.public_uuid);
        return next;
      });
      setBatchError(null);
    },
    [],
  );

  const removeSelection = useCallback((uuid: string) => {
    setSelection((prev) => {
      const next = new Map(prev);
      next.delete(uuid);
      return next;
    });
    setPerReportErrors((prev) => {
      if (!prev.has(uuid)) return prev;
      const next = new Map(prev);
      next.delete(uuid);
      return next;
    });
  }, []);

  const updateSelectionConfig = useCallback(
    (uuid: string, patch: Partial<Pick<SelectedLinkConfig, "linkType" | "note">>) => {
      setSelection((prev) => {
        const existing = prev.get(uuid);
        if (!existing) return prev;
        const next = new Map(prev);
        next.set(uuid, { ...existing, ...patch });
        return next;
      });
    },
    [],
  );

  const handleClose = () => {
    if (isSubmitting) return;
    onClose();
  };

  const handleSubmit = async () => {
    if (selectedCount === 0 || hasNoteLengthViolation) return;

    const entries = Array.from(selection.entries());
    setIsSubmitting(true);
    setBatchError(null);
    setPerReportErrors(new Map());

    const results = await Promise.allSettled(
      entries.map(([uuid, cfg]) =>
        linkIntakeToIncident(incidentPublicUuid, {
          intakeReportPublicUuid: uuid,
          linkType: cfg.linkType,
          note: cfg.note.trim() || undefined,
        }).then(() => uuid),
      ),
    );

    const succeededUuids = new Set<string>();
    const failed = new Map<string, string>();

    results.forEach((result, index) => {
      const [uuid] = entries[index];
      if (result.status === "fulfilled") {
        succeededUuids.add(result.value);
      } else {
        failed.set(uuid, mapLinkReportToIncidentError(result.reason));
      }
    });

    const totalCount = entries.length;
    const successCount = succeededUuids.size;
    const failedCount = failed.size;

    if (successCount > 0) {
      setCandidates((prev) =>
        prev.filter((report) => !succeededUuids.has(report.public_uuid)),
      );
      setSelection((prev) => {
        const next = new Map(prev);
        for (const uuid of succeededUuids) {
          next.delete(uuid);
        }
        return next;
      });

      await onSuccess();
    }

    if (successCount === totalCount) {
      toast.success(
        successCount === 1
          ? "Report linked to incident."
          : `${successCount} reports linked to incident.`,
      );
      resetFormState();
      onClose();
    } else if (successCount > 0 && failedCount > 0) {
      setPerReportErrors(failed);
      setBatchError(null);
      toast.message(
        `${successCount} of ${totalCount} reports linked. ${failedCount} could not be linked.`,
      );
    } else {
      setPerReportErrors(failed);
      setBatchError(
        "Unable to link the selected reports. Review the errors and try again.",
      );
    }

    setIsSubmitting(false);
  };

  if (!open) return null;

  const primaryLabel =
    selectedCount === 0
      ? "Link Report"
      : selectedCount === 1
        ? "Link Report"
        : "Link Reports";

  const dialog = (
    <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/40 px-4 py-6">
      <div
        className="flex max-h-[min(90vh,720px)] w-full max-w-3xl flex-col rounded-2xl border border-slate-200 bg-white shadow-xl"
        role="dialog"
        aria-labelledby="link-report-title"
        aria-modal="true"
        onClick={(event) => event.stopPropagation()}
      >
        <div className="shrink-0 border-b border-slate-100 px-5 py-4">
          <h2
            id="link-report-title"
            className="text-lg font-semibold text-slate-900"
          >
            Link Reports to Incident
          </h2>
          <p className="mt-2 text-sm text-slate-600">
            Select one or more intake reports to attach to{" "}
            <span className="font-medium text-slate-800">{incidentTitle}</span>.
          </p>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
          <div
            className={`grid min-h-0 gap-4 ${
              selectedCount > 0 ? "md:grid-cols-2" : "grid-cols-1"
            }`}
          >
            <div className="flex min-h-0 flex-col space-y-3">
              <FieldLabel required>Intake Reports</FieldLabel>
              <label className="block">
                <span className="sr-only">Search reports</span>
                <input
                  type="search"
                  value={searchQuery}
                  onChange={(event) => setSearchQuery(event.target.value)}
                  placeholder="Search reports"
                  className={triageFieldClassName}
                  disabled={isSubmitting || isLoadingCandidates}
                />
              </label>

              {selectedCount > 0 ? (
                <p className="text-sm font-medium text-slate-700">
                  {selectedCount} report{selectedCount === 1 ? "" : "s"} selected
                </p>
              ) : null}

              {isLoadingCandidates ? (
                <p className="text-sm text-slate-600">
                  Loading available intake reports…
                </p>
              ) : loadError ? (
                <div className="space-y-3">
                  <ErrorAlert message={loadError} />
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    onClick={() => void loadCandidates()}
                    disabled={isSubmitting}
                  >
                    Retry
                  </Button>
                </div>
              ) : filteredCandidates.length === 0 ? (
                <p className="text-sm text-slate-600">
                  {candidates.length === 0
                    ? "No available intake reports can be linked to this incident."
                    : "No reports match your search."}
                </p>
              ) : (
                <ul className="max-h-[min(50vh,360px)] space-y-2 overflow-y-auto pr-1">
                  {filteredCandidates.map((report) => (
                    <li key={report.public_uuid}>
                      <CandidateRow
                        report={report}
                        selected={selection.has(report.public_uuid)}
                        disabled={isSubmitting}
                        onToggle={() => toggleSelection(report)}
                      />
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {selectedCount > 0 ? (
              <div className="flex min-h-0 flex-col space-y-2">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Selected reports
                </p>
                <div className="max-h-[min(50vh,360px)] space-y-2 overflow-y-auto pr-1">
                  {selectedEntries.map(([uuid, config]) => (
                    <SelectedReportConfigRow
                      key={uuid}
                      config={config}
                      error={perReportErrors.get(uuid)}
                      disabled={isSubmitting}
                      onRemove={() => removeSelection(uuid)}
                      onLinkTypeChange={(linkType) =>
                        updateSelectionConfig(uuid, { linkType })
                      }
                      onNoteChange={(note) =>
                        updateSelectionConfig(uuid, { note })
                      }
                    />
                  ))}
                </div>
              </div>
            ) : null}
          </div>

          {batchError ? (
            <div className="mt-4">
              <ErrorAlert message={batchError} />
            </div>
          ) : null}
        </div>

        <div className="flex shrink-0 justify-end gap-2 border-t border-slate-100 px-5 py-4">
          <Button
            type="button"
            variant="secondary"
            onClick={handleClose}
            disabled={isSubmitting}
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant="primary"
            onClick={() => void handleSubmit()}
            isLoading={isSubmitting}
            disabled={
              selectedCount === 0 ||
              isSubmitting ||
              hasNoteLengthViolation
            }
          >
            {isSubmitting ? "Linking…" : primaryLabel}
          </Button>
        </div>
      </div>
    </div>
  );

  if (typeof document === "undefined") {
    return null;
  }

  return createPortal(dialog, document.body);
}
