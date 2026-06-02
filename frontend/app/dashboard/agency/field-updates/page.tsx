"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { AgencyAddResponseLogModal } from "@/components/agency/AgencyAddResponseLogModal";
import { AgencyDashboardPage } from "@/components/agency/AgencyDashboardPage";
import { AgencyIncidentRow } from "@/components/agency/AgencyIncidentRow";
import { AgencyResponseLogList } from "@/components/agency/AgencyResponseLogList";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { EmptyState } from "@/components/ui/StatusState";
import { AgencySkeletonBlock } from "@/components/agency/AgencySkeletonBlock";
import {
  getAgencyDispatches,
  getAgencyIncidents,
  getAgencyIncidentResponseLogs,
  getAgencyMe,
} from "@/lib/agency-api";
import { AGENCY_FIELD_UPDATES_SUBTITLE } from "@/lib/agency-dashboard";
import { filterDispatchesByIncident } from "@/lib/agency-dispatch-utils";
import {
  groupDispatchesByIncident,
  selectDefaultIncidentUuid,
} from "@/lib/agency-incident-utils";
import { getFieldUpdatesHelperText } from "@/lib/agency-microcopy";
import type { AgencyDispatch, AgencyIncident, AgencyResponseLog } from "@/types/agency";

export default function AgencyFieldUpdatesPage() {
  const [incidents, setIncidents] = useState<AgencyIncident[]>([]);
  const [dispatches, setDispatches] = useState<AgencyDispatch[]>([]);
  const [agencyTypeCode, setAgencyTypeCode] = useState<string | null>(null);
  const [logs, setLogs] = useState<AgencyResponseLog[]>([]);
  const [selectedIncidentUuid, setSelectedIncidentUuid] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [logsLoading, setLogsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [logModalOpen, setLogModalOpen] = useState(false);

  const groupedIncidents = useMemo(
    () => groupDispatchesByIncident(dispatches, incidents),
    [dispatches, incidents],
  );

  const selectedIncident = useMemo(
    () =>
      groupedIncidents.find((i) => i.incidentPublicUuid === selectedIncidentUuid) ??
      null,
    [groupedIncidents, selectedIncidentUuid],
  );

  const loadIncidents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [meRes, incidentsRes, dispatchesRes] = await Promise.all([
        getAgencyMe(),
        getAgencyIncidents({ limit: 100 }),
        getAgencyDispatches({ limit: 100 }),
      ]);
      setAgencyTypeCode(meRes.agency.agency_type_code);
      const incidentItems = incidentsRes.incidents ?? [];
      const dispatchItems = dispatchesRes.dispatches ?? [];
      setIncidents(incidentItems);
      setDispatches(dispatchItems);
      const grouped = groupDispatchesByIncident(dispatchItems, incidentItems);
      setSelectedIncidentUuid(
        (current) => current ?? selectDefaultIncidentUuid(grouped),
      );
    } catch {
      setError("Unable to load incidents. Please try again.");
    } finally {
      setLoading(false);
    }
  }, []);

  const loadLogs = useCallback(async (incidentPublicUuid: string) => {
    setLogsLoading(true);
    try {
      const data = await getAgencyIncidentResponseLogs(incidentPublicUuid, {
        limit: 100,
      });
      setLogs(data.response_logs ?? []);
    } catch {
      setLogs([]);
    } finally {
      setLogsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadIncidents();
  }, [loadIncidents]);

  useEffect(() => {
    if (!selectedIncidentUuid) {
      setLogs([]);
      return;
    }
    void loadLogs(selectedIncidentUuid);
  }, [selectedIncidentUuid, loadLogs]);

  const incidentDispatches = useMemo(() => {
    if (!selectedIncidentUuid) return [];
    return filterDispatchesByIncident(dispatches, selectedIncidentUuid);
  }, [dispatches, selectedIncidentUuid]);

  const defaultDispatch = incidentDispatches[0] ?? null;

  return (
    <AgencyDashboardPage>
      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <header className="mb-4 shrink-0">
          <h2 className="text-xl font-semibold text-slate-900">Field Updates</h2>
          <p className="mt-0.5 text-sm text-slate-600">{AGENCY_FIELD_UPDATES_SUBTITLE}</p>
          <p className="mt-1 text-xs text-slate-500">
            {getFieldUpdatesHelperText(agencyTypeCode)}
          </p>
        </header>

        {error ? (
          <div className="mb-4 shrink-0">
            <ErrorAlert message={error} />
          </div>
        ) : null}

        <div className="grid min-h-0 flex-1 gap-4 lg:grid-cols-[minmax(280px,38fr)_minmax(0,62fr)] lg:overflow-hidden">
          <section className="flex min-h-0 flex-col overflow-hidden rounded-2xl border border-slate-200/80 bg-white p-4 shadow-sm">
            <h3 className="mb-3 shrink-0 text-sm font-semibold text-slate-900">
              Assigned Incidents
            </h3>
            <div className="min-h-0 flex-1 overflow-y-auto pr-0.5">
              {loading ? (
                <AgencySkeletonBlock className="h-24 w-full" />
              ) : groupedIncidents.length === 0 ? (
                <EmptyState
                  title="No assigned incidents"
                  description="Select an incident with agency dispatches to record field updates."
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
                      onSelect={(item) =>
                        setSelectedIncidentUuid(item.incidentPublicUuid)
                      }
                    />
                  ))}
                </div>
              )}
            </div>
          </section>

          <section className="flex min-h-0 flex-col overflow-hidden rounded-2xl border border-slate-200/80 bg-white p-4 shadow-sm">
            <div className="mb-3 flex shrink-0 items-center justify-between gap-2">
              <div>
                <h3 className="text-sm font-semibold text-slate-900">Field Updates</h3>
                {selectedIncident ? (
                  <p className="text-xs text-slate-600">{selectedIncident.title}</p>
                ) : null}
              </div>
              {selectedIncidentUuid ? (
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => setLogModalOpen(true)}
                >
                  + Add Field Update
                </Button>
              ) : null}
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto pr-0.5">
              {!selectedIncidentUuid ? (
                <EmptyState
                  title="Select an incident"
                  description="Choose an assigned incident to view or add field updates."
                />
              ) : (
                <AgencyResponseLogList logs={logs} loading={logsLoading} />
              )}
            </div>
          </section>
        </div>
      </div>

      <AgencyAddResponseLogModal
        open={logModalOpen}
        incidentPublicUuid={selectedIncidentUuid}
        defaultDispatch={defaultDispatch}
        relatedDispatches={incidentDispatches}
        onClose={() => setLogModalOpen(false)}
        onSuccess={async () => {
          if (selectedIncidentUuid) {
            await loadLogs(selectedIncidentUuid);
          }
        }}
      />
    </AgencyDashboardPage>
  );
}
