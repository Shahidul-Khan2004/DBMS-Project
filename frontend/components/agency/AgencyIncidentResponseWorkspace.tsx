"use client";

import { useState } from "react";
import { AgencyAddResponseLogModal } from "@/components/agency/AgencyAddResponseLogModal";
import { AgencyAssignedUnitRow } from "@/components/agency/AgencyAssignedUnitRow";
import { AgencyDispatcherNotesList } from "@/components/agency/AgencyDispatcherNotesList";
import { AgencyResponseLogList } from "@/components/agency/AgencyResponseLogList";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/StatusState";
import { formatReadableLabel } from "@/lib/agency-dispatch-utils";
import {
  getDispatchStatusSummary,
  getIncidentLatestUpdateLabel,
  getUnitTypeForDispatch,
} from "@/lib/agency-incident-utils";
import type { GroupedAgencyIncident } from "@/lib/agency-incident-utils";
import type {
  AgencyDispatch,
  AgencyDispatchStatusAction,
  AgencyNote,
  AgencyResponseLog,
  AgencyUnit,
} from "@/types/agency";

type WorkspaceTab = "overview" | "units" | "field-updates" | "dispatcher-notes";

const TABS: Array<{ id: WorkspaceTab; label: string }> = [
  { id: "overview", label: "Overview" },
  { id: "units", label: "Assigned Units" },
  { id: "field-updates", label: "Field Updates" },
  { id: "dispatcher-notes", label: "Dispatcher Notes" },
];

function OverviewMetricTile({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-slate-200/80 bg-slate-50/80 px-3 py-2.5">
      <p className="text-[11px] font-medium uppercase tracking-wide text-slate-500">
        {label}
      </p>
      <p className="mt-1 text-sm font-semibold text-slate-900">{value}</p>
    </div>
  );
}

export function AgencyIncidentResponseWorkspace({
  incident,
  units,
  responseLogs,
  notes,
  logsLoading,
  notesLoading,
  compact = false,
  onStatusAction,
  onRefreshLogs,
}: {
  incident: GroupedAgencyIncident | null;
  units: AgencyUnit[];
  responseLogs: AgencyResponseLog[];
  notes: AgencyNote[];
  logsLoading: boolean;
  notesLoading: boolean;
  compact?: boolean;
  onStatusAction: (
    dispatch: AgencyDispatch,
    action: AgencyDispatchStatusAction,
  ) => void;
  onRefreshLogs: () => Promise<void>;
}) {
  const [activeTab, setActiveTab] = useState<WorkspaceTab>("overview");
  const [logModalOpen, setLogModalOpen] = useState(false);
  const [defaultDispatch, setDefaultDispatch] = useState<AgencyDispatch | null>(null);

  if (!incident) {
    return (
      <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50/50 px-3 py-4 text-center">
        <p className="text-sm font-medium text-slate-800">No incident selected</p>
        <p className="mt-1 text-xs text-slate-600">
          Select an assigned incident to view field response details.
        </p>
      </div>
    );
  }

  const assignedUnitsLabel = `${incident.assignedUnitCount} assigned unit${
    incident.assignedUnitCount === 1 ? "" : "s"
  }`;
  const hasMetaRow =
    Boolean(incident.highestPriority) ||
    Boolean(incident.statusCode) ||
    Boolean(incident.participationStatus) ||
    incident.assignedUnitCount > 0;

  const openFieldUpdateModal = (dispatch?: AgencyDispatch) => {
    setDefaultDispatch(dispatch ?? incident.dispatches[0] ?? null);
    setLogModalOpen(true);
  };

  return (
    <div className="flex h-full min-h-0 flex-1 flex-col">
      <header className={`shrink-0 space-y-1.5 ${compact ? "pb-3" : "pb-4"}`}>
        <p
          className={`font-semibold leading-snug text-slate-900 ${
            compact ? "text-base" : "text-lg"
          }`}
        >
          {incident.title}
        </p>
        {hasMetaRow ? (
          <div className="flex flex-wrap items-center gap-1.5 text-xs text-slate-700">
            {incident.highestPriority ? (
              <Badge tone={incident.highestPriority}>
                {formatBadgeLabel(incident.highestPriority)}
              </Badge>
            ) : null}
            {incident.highestPriority &&
            (incident.statusCode || incident.participationStatus) ? (
              <span className="text-slate-400" aria-hidden>
                ·
              </span>
            ) : null}
            {incident.statusCode ? (
              <Badge tone={incident.statusCode}>
                {formatReadableLabel(incident.statusCode)}
              </Badge>
            ) : incident.participationStatus ? (
              <Badge tone="info">
                {formatReadableLabel(incident.participationStatus)}
              </Badge>
            ) : null}
            {(incident.highestPriority || incident.statusCode || incident.participationStatus) &&
            incident.assignedUnitCount > 0 ? (
              <span className="text-slate-400" aria-hidden>
                ·
              </span>
            ) : null}
            {incident.assignedUnitCount > 0 ? (
              <span className="text-slate-700">{assignedUnitsLabel}</span>
            ) : null}
          </div>
        ) : null}
        <p className="text-xs text-slate-500">{incident.incidentCode}</p>
      </header>

      <div className="mb-3 flex shrink-0 flex-nowrap gap-1 overflow-x-auto border-b border-slate-200 [scrollbar-width:thin]">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveTab(tab.id)}
            className={`shrink-0 whitespace-nowrap rounded-t-md px-3 py-1.5 text-xs font-medium transition-colors ${
              activeTab === tab.id
                ? "bg-[#002D62] text-white"
                : "text-slate-600 hover:bg-slate-100"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto pb-5 pr-0.5 [scrollbar-color:theme(colors.slate.300)_transparent] [scrollbar-width:thin]">
        {activeTab === "overview" ? (
          <div className="grid grid-cols-2 gap-3">
            <OverviewMetricTile
              label="Dispatch summary"
              value={getDispatchStatusSummary(incident.dispatches)}
            />
            <OverviewMetricTile
              label="Latest update"
              value={getIncidentLatestUpdateLabel(incident.latestUpdateAt)}
            />
            {incident.participationStatus ? (
              <OverviewMetricTile
                label="Participation"
                value={formatReadableLabel(incident.participationStatus)}
              />
            ) : null}
            <OverviewMetricTile
              label="Assigned units"
              value={String(incident.assignedUnitCount)}
            />
          </div>
        ) : null}

        {activeTab === "units" ? (
          incident.dispatches.length === 0 ? (
            <EmptyState
              title="No assigned units"
              description="Units assigned to this incident will appear here."
            />
          ) : (
            <div className="space-y-2">
              {incident.dispatches.map((dispatch) => (
                <AgencyAssignedUnitRow
                  key={dispatch.public_uuid}
                  dispatch={dispatch}
                  unitTypeCode={getUnitTypeForDispatch(dispatch, units)}
                  onStatusAction={onStatusAction}
                  onAddFieldUpdate={openFieldUpdateModal}
                />
              ))}
            </div>
          )
        ) : null}

        {activeTab === "field-updates" ? (
          <div className="space-y-3">
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => openFieldUpdateModal()}
            >
              + Add Field Update
            </Button>
            <AgencyResponseLogList
              logs={responseLogs}
              loading={logsLoading}
              emptyTitle="No field updates"
              emptyDescription="Formal field updates for this incident will appear here."
            />
          </div>
        ) : null}

        {activeTab === "dispatcher-notes" ? (
          <AgencyDispatcherNotesList notes={notes} loading={notesLoading} />
        ) : null}
      </div>

      <AgencyAddResponseLogModal
        open={logModalOpen}
        incidentPublicUuid={incident.incidentPublicUuid}
        defaultDispatch={defaultDispatch}
        relatedDispatches={incident.dispatches}
        onClose={() => setLogModalOpen(false)}
        onSuccess={onRefreshLogs}
      />
    </div>
  );
}
