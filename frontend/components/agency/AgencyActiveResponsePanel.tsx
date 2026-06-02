"use client";

import { useState } from "react";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { EmptyState } from "@/components/ui/StatusState";
import { AgencyAddResponseLogModal } from "@/components/agency/AgencyAddResponseLogModal";
import { AgencyOperatorNotesList } from "@/components/agency/AgencyOperatorNotesList";
import { AgencyResponseLogList } from "@/components/agency/AgencyResponseLogList";
import {
  formatReadableLabel,
  getDispatchActionLabel,
  getNextDispatchAction,
  isTerminalDispatch,
} from "@/lib/agency-dispatch-utils";
import { formatRelativeAge } from "@/lib/format-relative-age";
import type {
  AgencyDispatch,
  AgencyDispatchStatusAction,
  AgencyNote,
  AgencyResponseLog,
} from "@/types/agency";

type TabId = "brief" | "timeline" | "logs" | "notes";

const TABS: Array<{ id: TabId; label: string }> = [
  { id: "brief", label: "Brief" },
  { id: "timeline", label: "Timeline" },
  { id: "logs", label: "Response Logs" },
  { id: "notes", label: "Operator Notes" },
];

function TimelineTab({ dispatch }: { dispatch: AgencyDispatch }) {
  const events = [
    { label: "Assigned", at: dispatch.assigned_at },
    { label: "Dispatched", at: dispatch.dispatched_at },
    { label: "Arrived", at: dispatch.arrived_at },
    { label: "Completed", at: dispatch.completed_at },
    { label: "Cancelled", at: dispatch.cancelled_at },
  ].filter((event) => event.at);

  if (events.length === 0) {
    return (
      <p className="text-sm text-slate-500">No timeline events recorded yet.</p>
    );
  }

  return (
    <ol className="space-y-3 border-l-2 border-slate-200 pl-4">
      {events.map((event) => (
        <li key={event.label} className="relative">
          <span className="absolute -left-[1.3rem] top-1 h-2.5 w-2.5 rounded-full bg-[#002D62]" />
          <p className="text-sm font-medium text-slate-900">{event.label}</p>
          <p className="text-xs text-slate-600">
            {event.at ? formatRelativeAge(event.at) : "—"}
          </p>
        </li>
      ))}
    </ol>
  );
}

export function AgencyActiveResponsePanel({
  dispatch,
  responseLogs,
  notes,
  logsLoading,
  notesLoading,
  relatedDispatches,
  onStatusAction,
  onRefreshLogs,
}: {
  dispatch: AgencyDispatch | null;
  responseLogs: AgencyResponseLog[];
  notes: AgencyNote[];
  logsLoading: boolean;
  notesLoading: boolean;
  relatedDispatches: AgencyDispatch[];
  onStatusAction: (
    dispatch: AgencyDispatch,
    action: AgencyDispatchStatusAction,
  ) => void;
  onRefreshLogs: () => Promise<void>;
}) {
  const [activeTab, setActiveTab] = useState<TabId>("brief");
  const [logModalOpen, setLogModalOpen] = useState(false);

  if (!dispatch) {
    return (
      <EmptyState
        title="No active dispatch selected"
        description="Assigned dispatches will appear here when your agency is attached to an incident."
      />
    );
  }

  const nextAction = getNextDispatchAction(dispatch.status_code);
  const readOnly = isTerminalDispatch(dispatch.status_code);

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="mb-3 flex shrink-0 flex-wrap gap-1 border-b border-slate-200">
        {TABS.map((tab) => (
          <button
            key={tab.id}
            type="button"
            onClick={() => setActiveTab(tab.id)}
            className={`rounded-t-md px-3 py-1.5 text-xs font-medium transition-colors ${
              activeTab === tab.id
                ? "bg-[#002D62] text-white"
                : "text-slate-600 hover:bg-slate-100"
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto pr-0.5">
        {activeTab === "brief" ? (
          <div className="space-y-3 text-sm">
            <div>
              <p className="font-semibold text-slate-900">
                {dispatch.incident.title || dispatch.incident.incident_code}
              </p>
              <p className="text-xs text-slate-600">{dispatch.incident.incident_code}</p>
            </div>
            <dl className="grid gap-2 text-xs sm:grid-cols-2">
              <div>
                <dt className="text-slate-500">Dispatch status</dt>
                <dd className="mt-0.5">
                  <Badge tone={dispatch.status_code}>
                    {formatReadableLabel(dispatch.status_code)}
                  </Badge>
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">Priority</dt>
                <dd className="mt-0.5">
                  <Badge tone={dispatch.priority_level}>
                    {formatBadgeLabel(dispatch.priority_level)}
                  </Badge>
                </dd>
              </div>
              <div>
                <dt className="text-slate-500">Assigned unit</dt>
                <dd className="mt-0.5 font-medium text-slate-800">
                  {dispatch.unit.unit_name} · {dispatch.unit.unit_code}
                </dd>
              </div>
            </dl>
            {!readOnly && nextAction ? (
              <Button
                type="button"
                size="sm"
                variant="primary"
                onClick={() => onStatusAction(dispatch, nextAction)}
              >
                {getDispatchActionLabel(nextAction)}
              </Button>
            ) : null}
          </div>
        ) : null}

        {activeTab === "timeline" ? <TimelineTab dispatch={dispatch} /> : null}

        {activeTab === "logs" ? (
          <div className="space-y-3">
            <Button
              type="button"
              size="sm"
              variant="outline"
              onClick={() => setLogModalOpen(true)}
            >
              + Add Field Update
            </Button>
            <AgencyResponseLogList logs={responseLogs} loading={logsLoading} />
          </div>
        ) : null}

        {activeTab === "notes" ? (
          <AgencyOperatorNotesList notes={notes} loading={notesLoading} />
        ) : null}
      </div>

      <AgencyAddResponseLogModal
        open={logModalOpen}
        incidentPublicUuid={dispatch.incident.public_uuid}
        defaultDispatch={dispatch}
        relatedDispatches={relatedDispatches}
        onClose={() => setLogModalOpen(false)}
        onSuccess={onRefreshLogs}
      />
    </div>
  );
}
