"use client";

import { useMemo } from "react";
import { IncidentCommandActivityReportsCard } from "@/components/dispatcher/incidents/command/IncidentCommandActivityReportsCard";
import { IncidentCommandResponseOperationsCard } from "@/components/dispatcher/incidents/command/IncidentCommandResponseOperationsCard";
import { IncidentCommandSummaryCard } from "@/components/dispatcher/incidents/command/IncidentCommandSummaryCard";
import { buildIncidentActivityTimeline } from "@/lib/build-incident-activity-timeline";
import { FINAL_INCIDENT_STATUSES, isTerminalIncident } from "@/lib/incident-status";
import type {
  DispatchStatusAction,
  IncidentDetailResponse,
  IncidentDispatch,
  LinkedIntakeReport,
} from "@/types/incident-command";

const ELIGIBLE_PARTICIPATION_STATUSES = new Set(["requested", "active"]);

function hasEligibleParticipatingAgency(detail: IncidentDetailResponse) {
  return detail.participatingAgencies.some((agency) =>
    ELIGIBLE_PARTICIPATION_STATUSES.has(agency.participationStatus),
  );
}

function getDispatchDisabledReason(detail: IncidentDetailResponse) {
  if (FINAL_INCIDENT_STATUSES.has(detail.status)) {
    return "Dispatch is unavailable for terminal incidents.";
  }
  if (!hasEligibleParticipatingAgency(detail)) {
    return "Assign a participating agency before dispatching units.";
  }
  return undefined;
}

export function IncidentCommandWorkspace({
  detail,
  incidentPublicUuid,
  opsMutationGeneration,
  canEditLocation = false,
  onOpenDetails,
  onEditLocation,
  onAssignAgency,
  onDispatchUnit,
  onDispatchStatusAction,
  onRefreshDetail,
  onViewReportDetails,
}: {
  detail: IncidentDetailResponse;
  incidentPublicUuid: string;
  opsMutationGeneration: number;
  canEditLocation?: boolean;
  onOpenDetails: () => void;
  onEditLocation: () => void;
  onAssignAgency: () => void;
  onDispatchUnit: () => void;
  onDispatchStatusAction: (
    dispatch: IncidentDispatch,
    targetStatus: DispatchStatusAction,
  ) => void;
  onRefreshDetail: () => Promise<void>;
  onViewReportDetails: (report: LinkedIntakeReport) => void;
}) {
  const terminal = isTerminalIncident(detail.status);
  const canAssignAgency = !terminal;
  const canDispatchUnits =
    hasEligibleParticipatingAgency(detail) && !terminal;
  const dispatchDisabledReason = getDispatchDisabledReason(detail);
  const assignAgencyDisabledReason = terminal
    ? "Agency assignment is unavailable for terminal incidents."
    : undefined;
  const activityTimeline = useMemo(
    () => buildIncidentActivityTimeline(detail),
    [detail],
  );

  return (
    <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 lg:grid-cols-[minmax(0,55fr)_minmax(0,45fr)] lg:items-stretch lg:gap-3 lg:overflow-hidden">
      <div className="flex min-h-0 flex-col gap-4 lg:min-h-0 lg:gap-3 lg:overflow-hidden">
        <IncidentCommandSummaryCard
          detail={detail}
          canEditLocation={canEditLocation}
          onOpenDetails={onOpenDetails}
          onEditLocation={onEditLocation}
          className="shrink-0"
        />
        <IncidentCommandResponseOperationsCard
          incidentPublicUuid={incidentPublicUuid}
          agencies={detail.participatingAgencies}
          dispatches={detail.dispatches}
          canAssignAgency={canAssignAgency}
          assignAgencyDisabledReason={assignAgencyDisabledReason}
          canDispatchUnits={canDispatchUnits}
          dispatchDisabledReason={dispatchDisabledReason}
          incidentIsTerminal={terminal}
          opsMutationGeneration={opsMutationGeneration}
          onAssignAgency={onAssignAgency}
          onDispatchUnit={onDispatchUnit}
          onDispatchStatusAction={onDispatchStatusAction}
          className="min-h-0 flex-1 lg:min-h-0"
        />
      </div>

      <div className="flex min-h-0 flex-col lg:min-h-0 lg:overflow-hidden">
        <IncidentCommandActivityReportsCard
          activityTimeline={activityTimeline}
          reports={detail.linkedIntakeReports}
          timelinePreview={detail.timelinePreview}
          incidentPublicUuid={incidentPublicUuid}
          incidentTitle={detail.title}
          onRefreshDetail={onRefreshDetail}
          onViewReportDetails={onViewReportDetails}
          className="min-h-0 flex-1 lg:h-full"
        />
      </div>
    </div>
  );
}
