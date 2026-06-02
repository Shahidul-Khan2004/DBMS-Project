"use client";

import { useState } from "react";
import { AgencyCommandCenterColumnPanel } from "@/components/agency/AgencyCommandCenterColumnPanel";
import { AgencyDashboardPage } from "@/components/agency/AgencyDashboardPage";
import { AgencyDispatchStatusModal } from "@/components/agency/AgencyDispatchStatusModal";
import { AgencyIncidentRow } from "@/components/agency/AgencyIncidentRow";
import { AgencyIncidentResponseWorkspace } from "@/components/agency/AgencyIncidentResponseWorkspace";
import { AgencyUnitsPanel } from "@/components/agency/AgencyUnitsPanel";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { AgencySkeletonBlock } from "@/components/agency/AgencySkeletonBlock";
import {
  AGENCY_COMMAND_CENTER_SUBTITLE,
  AGENCY_COMMAND_CENTER_TITLE,
} from "@/lib/agency-dashboard";
import { countAvailableUnits, countBusyUnits } from "@/lib/agency-incident-utils";
import { useAgencyCommandCenter } from "@/lib/hooks/use-agency-command-center";

function CommandCenterPanelEmpty({
  title,
  description,
}: {
  title: string;
  description: string;
}) {
  return (
    <div className="rounded-lg border border-dashed border-slate-200 bg-slate-50/50 px-3 py-4 text-center">
      <p className="text-sm font-medium text-slate-800">{title}</p>
      <p className="mt-1 text-xs text-slate-600">{description}</p>
    </div>
  );
}

export default function AgencyCommandCenterPage() {
  const [addUnitOpen, setAddUnitOpen] = useState(false);
  const {
    me,
    groupedIncidents,
    selectedIncident,
    selectedIncidentUuid,
    setSelectedIncidentUuid,
    units,
    responseLogs,
    notes,
    meLoading,
    dispatchesLoading,
    unitsLoading,
    logsLoading,
    notesLoading,
    accessError,
    dispatchesError,
    unitsError,
    isRefreshing,
    statusModal,
    setStatusModal,
    refreshAll,
    openStatusAction,
    handleDispatchStatusSuccess,
    refreshLogs,
    refreshUnitsAndCounts,
  } = useAgencyCommandCenter();

  const assignedIncidentCount = groupedIncidents.length;
  const activeUnitCount = units.filter((u) => u.is_active).length;
  const totalUnits =
    unitsLoading || meLoading
      ? (me?.counts.active_units ?? null)
      : activeUnitCount;
  const availableCount = countAvailableUnits(units);
  const busyCount = countBusyUnits(units);
  const unitReadinessSubtitle =
    unitsLoading || meLoading
      ? "Manage unit availability"
      : units.length === 0
        ? "Manage unit availability"
        : `${availableCount} available · ${busyCount} busy`;

  return (
    <AgencyDashboardPage>
      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <header className="mb-3 flex shrink-0 flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-xl font-semibold text-slate-900">
              {AGENCY_COMMAND_CENTER_TITLE}
            </h2>
            <p className="mt-0.5 text-sm text-slate-600">{AGENCY_COMMAND_CENTER_SUBTITLE}</p>
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={isRefreshing || Boolean(accessError)}
            onClick={() => void refreshAll()}
          >
            {isRefreshing ? "Refreshing…" : "Refresh"}
          </Button>
        </header>

        {accessError ? (
          <div className="mb-3 shrink-0">
            <ErrorAlert message={accessError} />
          </div>
        ) : null}

        {accessError ? null : (
          <div className="grid min-h-0 flex-1 gap-4 lg:min-h-0 lg:grid-cols-[minmax(20rem,1fr)_minmax(28rem,1.25fr)_minmax(22rem,0.85fr)] lg:overflow-hidden">
            <AgencyCommandCenterColumnPanel
              title="Assigned Incidents"
              count={assignedIncidentCount}
              countLoading={dispatchesLoading || meLoading}
              subtitle="Dispatcher-assigned incident work"
            >
              {dispatchesError ? <ErrorAlert message={dispatchesError} /> : null}
              {dispatchesLoading ? (
                <div className="space-y-2" aria-busy="true">
                  <AgencySkeletonBlock className="h-24 w-full" />
                  <AgencySkeletonBlock className="h-24 w-full" />
                </div>
              ) : groupedIncidents.length === 0 ? (
                <CommandCenterPanelEmpty
                  title="No assigned incidents"
                  description="Dispatcher-assigned incident work will appear here."
                />
              ) : (
                <div className="space-y-2">
                  {groupedIncidents.map((incident) => (
                    <AgencyIncidentRow
                      key={incident.incidentPublicUuid}
                      incident={incident}
                      selected={selectedIncidentUuid === incident.incidentPublicUuid}
                      onSelect={(item) =>
                        setSelectedIncidentUuid(item.incidentPublicUuid)
                      }
                    />
                  ))}
                </div>
              )}
            </AgencyCommandCenterColumnPanel>

            <AgencyCommandCenterColumnPanel
              title="Active Response"
              count={selectedIncident ? 1 : 0}
              countLoading={false}
              subtitle="Incident context and field activity"
            >
              <AgencyIncidentResponseWorkspace
                incident={selectedIncident}
                units={units}
                responseLogs={responseLogs}
                notes={notes}
                logsLoading={logsLoading}
                notesLoading={notesLoading}
                compact
                onStatusAction={openStatusAction}
                onRefreshLogs={refreshLogs}
              />
            </AgencyCommandCenterColumnPanel>

            <AgencyCommandCenterColumnPanel
              title="Unit Readiness"
              count={totalUnits}
              countLoading={unitsLoading || meLoading}
              subtitle={unitReadinessSubtitle}
              headerAction={
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => setAddUnitOpen(true)}
                >
                  + Add Unit
                </Button>
              }
            >
              <AgencyUnitsPanel
                units={units}
                loading={unitsLoading}
                error={unitsError}
                showAddButton={false}
                addOpen={addUnitOpen}
                onAddOpenChange={setAddUnitOpen}
                onRefresh={refreshUnitsAndCounts}
              />
            </AgencyCommandCenterColumnPanel>
          </div>
        )}
      </div>

      <AgencyDispatchStatusModal
        open={Boolean(statusModal)}
        dispatch={statusModal?.dispatch ?? null}
        targetStatus={statusModal?.action ?? null}
        onClose={() => setStatusModal(null)}
        onSuccess={handleDispatchStatusSuccess}
      />
    </AgencyDashboardPage>
  );
}
