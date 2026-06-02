"use client";

import { AgencyDashboardPage } from "@/components/agency/AgencyDashboardPage";
import { AgencyDetailDrawer } from "@/components/agency/AgencyDetailDrawer";
import { AgencyDispatchStatusModal } from "@/components/agency/AgencyDispatchStatusModal";
import { AgencyIncidentRow } from "@/components/agency/AgencyIncidentRow";
import { AgencyIncidentResponseWorkspace } from "@/components/agency/AgencyIncidentResponseWorkspace";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { EmptyState } from "@/components/ui/StatusState";
import { AgencySkeletonBlock } from "@/components/agency/AgencySkeletonBlock";
import { AGENCY_RESPONSE_WORK_SUBTITLE } from "@/lib/agency-dashboard";
import { useAgencyResponseWork } from "@/lib/hooks/use-agency-response-work";
import { useState } from "react";

export default function AgencyResponseWorkPage() {
  const [drawerOpen, setDrawerOpen] = useState(false);
  const {
    units,
    groupedIncidents,
    selectedIncident,
    selectedIncidentUuid,
    setSelectedIncidentUuid,
    responseLogs,
    notes,
    loading,
    logsLoading,
    notesLoading,
    error,
    accessError,
    statusModal,
    setStatusModal,
    loadCore,
    handleDispatchStatusSuccess,
    refreshLogs,
    openStatusAction,
  } = useAgencyResponseWork();

  const selectIncident = (incidentPublicUuid: string) => {
    setSelectedIncidentUuid(incidentPublicUuid);
    if (typeof window !== "undefined" && window.innerWidth < 768) {
      setDrawerOpen(true);
    }
  };

  const workspace = (
    <AgencyIncidentResponseWorkspace
      incident={selectedIncident}
      units={units}
      responseLogs={responseLogs}
      notes={notes}
      logsLoading={logsLoading}
      notesLoading={notesLoading}
      onStatusAction={openStatusAction}
      onRefreshLogs={refreshLogs}
    />
  );

  return (
    <AgencyDashboardPage>
      <div className="flex min-h-0 flex-1 flex-col lg:overflow-hidden">
        <header className="mb-4 flex shrink-0 flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-xl font-semibold text-slate-900">Response Work</h2>
            <p className="mt-0.5 text-sm text-slate-600">{AGENCY_RESPONSE_WORK_SUBTITLE}</p>
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={loading || Boolean(accessError)}
            onClick={() => void loadCore()}
          >
            Refresh
          </Button>
        </header>

        {accessError || error ? (
          <div className="mb-4 shrink-0">
            <ErrorAlert message={accessError ?? error ?? ""} />
          </div>
        ) : null}

        {!accessError ? (
          <div className="flex min-h-0 flex-1 flex-col gap-4 lg:grid lg:items-start lg:gap-4 lg:grid-cols-[minmax(22rem,0.56fr)_minmax(40rem,1fr)]">
            <section className="h-fit w-full self-start overflow-hidden rounded-2xl border border-slate-200/80 bg-white p-4 shadow-sm">
              <header className="mb-3 shrink-0">
                <h3 className="text-sm font-semibold text-slate-900">
                  Assigned Incidents
                </h3>
                <p className="mt-0.5 text-xs text-slate-500">
                  Dispatcher-assigned incident work
                </p>
              </header>
              <div className="overflow-y-auto pr-0.5 [scrollbar-color:theme(colors.slate.300)_transparent] [scrollbar-width:thin] lg:max-h-[calc(100vh-24rem)]">
                {loading ? (
                  <div className="space-y-2" aria-busy="true">
                    <AgencySkeletonBlock className="h-24 w-full" />
                    <AgencySkeletonBlock className="h-24 w-full" />
                  </div>
                ) : groupedIncidents.length === 0 ? (
                  <EmptyState
                    title="No assigned incidents"
                    description="Dispatcher-assigned incident work will appear here."
                  />
                ) : (
                  <div className="space-y-2">
                    {groupedIncidents.map((incident) => (
                      <AgencyIncidentRow
                        key={incident.incidentPublicUuid}
                        incident={incident}
                        selected={
                          selectedIncidentUuid === incident.incidentPublicUuid
                        }
                        onSelect={(item) => selectIncident(item.incidentPublicUuid)}
                      />
                    ))}
                  </div>
                )}
              </div>
            </section>

            <section className="flex min-h-0 w-full flex-col self-start overflow-hidden rounded-2xl border border-slate-200/80 bg-white p-4 shadow-md lg:min-h-[calc(100vh-17rem)]">
              <div className="flex min-h-0 flex-1 flex-col">{workspace}</div>
            </section>
          </div>
        ) : null}
      </div>

      <AgencyDetailDrawer
        open={drawerOpen}
        title="Incident response"
        onClose={() => setDrawerOpen(false)}
      >
        {workspace}
      </AgencyDetailDrawer>

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
