"use client";

import {
  ARCHIVE_FINAL_STATE_OPTIONS,
  ARCHIVE_RECORD_TYPE_OPTIONS,
  getArchiveEmptyStateMessage,
  getArchiveFinalStateHelperText,
} from "@/components/dispatcher/archive/archiveConfig";
import { ArchiveIncidentsList } from "@/components/dispatcher/archive/ArchiveIncidentsList";
import { ArchiveSegmentedControl } from "@/components/dispatcher/archive/ArchiveSegmentedControl";
import { ArchiveServiceCasesList } from "@/components/dispatcher/archive/ArchiveServiceCasesList";
import type {
  ArchiveFinalState,
  ArchivePartialStreamError,
  ArchiveRecordType,
} from "@/components/dispatcher/archive/types";
import type {
  ActiveIncidentListItem,
  IncidentCardLocationState,
} from "@/components/dispatcher/incidents/types";
import type { OperationsIncidentRow } from "@/lib/operations-intake-triage";
import type { OperationsServiceCase } from "@/types/service-case";

interface ArchiveWorkspaceProps {
  recordType: ArchiveRecordType;
  finalState: ArchiveFinalState;
  onRecordTypeChange: (value: ArchiveRecordType) => void;
  onFinalStateChange: (value: ArchiveFinalState) => void;
  isLoading: boolean;
  error: string | null;
  partialError: ArchivePartialStreamError;
  incidentItems: ActiveIncidentListItem[];
  incidentSourceRows: OperationsIncidentRow[];
  getCardLocation: (publicUuid: string) => IncidentCardLocationState;
  serviceCases: OperationsServiceCase[];
  incidentHasMore: boolean;
  serviceCaseHasMore: boolean;
  onLoadMore: () => void;
  onRetry: () => void;
  onRetryPartialStream: (stream: "closed" | "escalated") => void;
  className?: string;
}

export function ArchiveWorkspace({
  recordType,
  finalState,
  onRecordTypeChange,
  onFinalStateChange,
  isLoading,
  error,
  partialError,
  incidentItems,
  incidentSourceRows,
  getCardLocation,
  serviceCases,
  incidentHasMore,
  serviceCaseHasMore,
  onLoadMore,
  onRetry,
  onRetryPartialStream,
  className = "",
}: ArchiveWorkspaceProps) {
  const emptyMessage = getArchiveEmptyStateMessage(recordType, finalState);
  const helperText = getArchiveFinalStateHelperText(recordType, finalState);
  const countLabel =
    recordType === "incidents"
      ? incidentItems.length === 1
        ? "1 incident"
        : `${incidentItems.length} incidents`
      : serviceCases.length === 1
        ? "1 case"
        : `${serviceCases.length} cases`;

  return (
    <section
      className={`flex min-h-0 flex-1 flex-col overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-sm lg:min-h-0 ${className}`.trim()}
      aria-label="Dispatcher archive"
    >
      <header className="shrink-0 border-b border-slate-100 px-4 py-4 sm:px-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-900">Dispatcher Archive</h3>
            <p className="mt-0.5 text-sm text-slate-600">
              Review terminal incidents and service cases by record type and final state.
            </p>
          </div>
          <span className="shrink-0 text-sm font-medium text-slate-600">{countLabel}</span>
        </div>

        <div className="mt-4 flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
          <ArchiveSegmentedControl
            label="Record Type"
            value={recordType}
            options={ARCHIVE_RECORD_TYPE_OPTIONS}
            onChange={onRecordTypeChange}
          />
          <ArchiveSegmentedControl
            label="Final State"
            value={finalState}
            options={ARCHIVE_FINAL_STATE_OPTIONS}
            onChange={onFinalStateChange}
          />
        </div>

        <p className="mt-3 text-xs text-slate-500">{helperText}</p>
      </header>

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        {recordType === "incidents" ? (
          <ArchiveIncidentsList
            className="min-h-0 flex-1"
            items={incidentItems}
            sourceRows={incidentSourceRows}
            getCardLocation={getCardLocation}
            emptyMessage={emptyMessage}
            isLoading={isLoading}
            error={error}
            hasMore={incidentHasMore}
            onRetry={onRetry}
            onLoadMore={onLoadMore}
          />
        ) : (
          <ArchiveServiceCasesList
            className="min-h-0 flex-1"
            items={serviceCases}
            emptyMessage={emptyMessage}
            isLoading={isLoading}
            error={error}
            partialError={partialError}
            hasMore={serviceCaseHasMore}
            onRetry={onRetry}
            onLoadMore={onLoadMore}
            onRetryPartialStream={onRetryPartialStream}
          />
        )}
      </div>
    </section>
  );
}
