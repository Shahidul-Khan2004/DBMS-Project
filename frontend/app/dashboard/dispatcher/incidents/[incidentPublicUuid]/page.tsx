"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { AttachIncidentToDisasterDialog } from "@/components/dispatcher/disasters/AttachIncidentToDisasterDialog";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { AssignParticipatingAgencyDialog } from "@/components/dispatcher/incidents/command/AssignParticipatingAgencyDialog";
import { DispatchStatusActionDialog } from "@/components/dispatcher/incidents/command/DispatchStatusActionDialog";
import { DispatchUnitDialog } from "@/components/dispatcher/incidents/command/DispatchUnitDialog";
import { DispatcherOpsShell } from "@/components/dispatcher/DispatcherOpsShell";
import { EditReportedLocationDialog } from "@/components/dispatcher/triage/EditReportedLocationDialog";
import { ReportedLocationHistoryDialog } from "@/components/dispatcher/triage/ReportedLocationHistoryDialog";
import {
  CancelIncidentDialog,
  CloseIncidentDialog,
  IncidentCommandDetailsDrawer,
  IncidentCommandHeader,
  IncidentCommandSkeleton,
  IncidentCommandWorkspace,
  ResolveIncidentDialog,
} from "@/components/dispatcher/incidents/command";
import {
  IntakeReportDetailsDrawer,
  type IntakeReportLinkContext,
} from "@/components/dispatcher/intake";
import { Button } from "@/components/ui/Button";
import { PageLoading } from "@/components/ui/StatusState";
import { ApiError, ensureAuthSession } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import { useDispatcherWorkspaceGuard } from "@/lib/use-dispatcher-workspace-guard";
import {
  DISPATCHER_DASHBOARD_SUBTITLE,
  DISPATCHER_DASHBOARD_TITLE,
} from "@/lib/dispatcher-dashboard";
import {
  deriveIncidentSourceLabel,
  getLocationSourceLinkedIntakeReport,
  getLocationSourceReportUuid,
  mapIncidentDetailToLocationEditItem,
  mapOperationsIncidentDetailResponse,
} from "@/lib/map-incident-command";
import { INCIDENT_SOURCE_NOT_AVAILABLE_LABEL } from "@/lib/incident-source-label";
import { isTerminalIncident } from "@/lib/incident-status";
import { getOperationsIncident } from "@/lib/operations-incident-api";
import { fetchIntakeReportDetail } from "@/lib/operations-intake-triage";
import type { OperationsIntakeReport } from "@/types/operations-intake";
import type {
  DispatchStatusAction,
  IncidentDetailResponse,
  IncidentDispatch,
  LinkedIntakeReport,
} from "@/types/incident-command";

const LOAD_ERROR_MESSAGE = "Incident details could not be retrieved. Try again.";

function getIncidentLoadErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 404) {
      return "This incident could not be found. It may have been removed or you may not have access.";
    }
    if (error.status === 0 || error.code === "NETWORK_ERROR") {
      return "Could not reach the server. Please try again.";
    }
    if (error.status === 403 || error.code === "FORBIDDEN") {
      return "You do not have permission to view this incident.";
    }
  }
  return LOAD_ERROR_MESSAGE;
}

export default function IncidentCommandPage() {
  const router = useRouter();
  const params = useParams();
  const incidentPublicUuid =
    typeof params.incidentPublicUuid === "string"
      ? params.incidentPublicUuid
      : "";

  const isChecking = useDispatcherWorkspaceGuard();
  const [detail, setDetail] = useState<IncidentDetailResponse | null>(null);
  const [isLoadingDetail, setIsLoadingDetail] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [detailsDrawerOpen, setDetailsDrawerOpen] = useState(false);
  const [intakeReportDrawer, setIntakeReportDrawer] = useState<{
    reportPublicUuid: string;
    linkContext: IntakeReportLinkContext;
  } | null>(null);
  const [assignAgencyOpen, setAssignAgencyOpen] = useState(false);
  const [dispatchUnitOpen, setDispatchUnitOpen] = useState(false);
  const [dispatchStatusAction, setDispatchStatusAction] = useState<{
    dispatch: IncidentDispatch;
    targetStatus: DispatchStatusAction;
  } | null>(null);
  const [resolveDialogOpen, setResolveDialogOpen] = useState(false);
  const [closeDialogOpen, setCloseDialogOpen] = useState(false);
  const [cancelDialogOpen, setCancelDialogOpen] = useState(false);
  const [attachDisasterDialogOpen, setAttachDisasterDialogOpen] = useState(false);
  const [locationDialogOpen, setLocationDialogOpen] = useState(false);
  const [historyDialogOpen, setHistoryDialogOpen] = useState(false);
  const [historyRefreshKey, setHistoryRefreshKey] = useState(0);
  const [opsMutationGeneration, setOpsMutationGeneration] = useState(0);
  const [sourceIntakeDetail, setSourceIntakeDetail] =
    useState<OperationsIntakeReport | null>(null);

  const goToActiveIncidents = useCallback(() => {
    router.push("/dashboard/dispatcher/incidents");
  }, [router]);

  const loadDetail = useCallback(async () => {
    if (!incidentPublicUuid) {
      setLoadError("Invalid incident link.");
      setDetail(null);
      setIsLoadingDetail(false);
      return;
    }

    const accessToken = await ensureAuthSession();
    if (!accessToken) {
      router.replace("/auth/login");
      return;
    }

    setIsLoadingDetail(true);
    setLoadError(null);

    try {
      const response = await getOperationsIncident(incidentPublicUuid);
      setDetail(mapOperationsIncidentDetailResponse(response));
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Failed to load incident command", err);
      }
      setLoadError(getIncidentLoadErrorMessage(err));
      setDetail(null);
    } finally {
      setIsLoadingDetail(false);
    }
  }, [incidentPublicUuid, router]);

  const refreshDetail = useCallback(async () => {
    if (!incidentPublicUuid) return;

    const accessToken = await ensureAuthSession();
    if (!accessToken) {
      router.replace("/auth/login");
      return;
    }

    try {
      const response = await getOperationsIncident(incidentPublicUuid);
      setDetail(mapOperationsIncidentDetailResponse(response));
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Failed to refresh incident command", err);
      }
      setLoadError(getIncidentLoadErrorMessage(err));
    }
  }, [incidentPublicUuid, router]);

  const refreshDetailAfterOpsMutation = useCallback(async () => {
    await refreshDetail();
    setOpsMutationGeneration((generation) => generation + 1);
  }, [refreshDetail]);

  const handleReportUnlinked = useCallback(
    async (reportPublicUuid: string) => {
      setDetail((current) =>
        current
          ? {
              ...current,
              linkedIntakeReports: current.linkedIntakeReports.filter(
                (report) => report.intakePublicUuid !== reportPublicUuid,
              ),
            }
          : current,
      );

      try {
        const response = await getOperationsIncident(incidentPublicUuid);
        setDetail(mapOperationsIncidentDetailResponse(response));
        setLoadError(null);
      } catch (err) {
        if (process.env.NODE_ENV === "development") {
          console.error("Failed to refresh incident after report unlink", err);
        }
      }
    },
    [incidentPublicUuid],
  );

  useEffect(() => {
    if (isChecking) return;
    void loadDetail();
  }, [isChecking, loadDetail]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  const participatingAgencyUuids =
    detail?.participatingAgencies.map((agency) => agency.agencyPublicUuid) ??
    [];
  const hasLeadAgency =
    detail?.participatingAgencies.some((agency) => agency.isLeadAgency) ??
    false;
  const locationSourceReport = useMemo(
    () => (detail ? getLocationSourceLinkedIntakeReport(detail) : null),
    [detail],
  );
  const locationSourceReportUuid = useMemo(
    () => (detail ? getLocationSourceReportUuid(detail) : null),
    [detail],
  );
  const canEditLocation = Boolean(locationSourceReportUuid);
  const locationEditItem = useMemo(
    () => (detail ? mapIncidentDetailToLocationEditItem(detail) : null),
    [detail],
  );

  useEffect(() => {
    if (!locationSourceReportUuid) {
      setSourceIntakeDetail(null);
      return;
    }

    setSourceIntakeDetail(null);

    let cancelled = false;

    void (async () => {
      try {
        const report = await fetchIntakeReportDetail(locationSourceReportUuid);
        if (!cancelled) setSourceIntakeDetail(report);
      } catch {
        if (!cancelled) setSourceIntakeDetail(null);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [locationSourceReportUuid]);

  const sourceLabel = useMemo(
    () =>
      detail
        ? deriveIncidentSourceLabel(detail, sourceIntakeDetail)
        : INCIDENT_SOURCE_NOT_AVAILABLE_LABEL,
    [detail, sourceIntakeDetail],
  );

  const handleEditLocation = useCallback(() => {
    if (!canEditLocation) return;
    setLocationDialogOpen(true);
  }, [canEditLocation]);

  const handleViewLocationHistory = useCallback(() => {
    if (!canEditLocation) return;
    setHistoryDialogOpen(true);
  }, [canEditLocation]);

  const refreshAfterLocationUpdate = useCallback(() => {
    void refreshDetail();
    if (historyDialogOpen) {
      setHistoryRefreshKey((key) => key + 1);
    }
  }, [refreshDetail, historyDialogOpen]);

  const handleViewLinkedReportDetails = useCallback(
    (report: LinkedIntakeReport) => {
      if (!detail) return;
      setIntakeReportDrawer({
        reportPublicUuid: report.intakePublicUuid,
        linkContext: {
          linkType: report.linkType,
          linkedAt: report.linkedAt,
          incidentTitle: detail.title,
          incidentCode: detail.incidentCode,
        },
      });
    },
    [detail],
  );

  const handleIntakeReportDrawerOpenChange = useCallback((open: boolean) => {
    if (!open) {
      setIntakeReportDrawer(null);
    }
  }, []);

  if (isChecking) {
    return <PageLoading label="Loading incident command" />;
  }

  return (
    <DashboardLayout
      title={DISPATCHER_DASHBOARD_TITLE}
      subtitle={DISPATCHER_DASHBOARD_SUBTITLE}
      onLogout={handleLogout}
      hideSidebar
      showHealthBadge={false}
      contentClassName="flex min-h-0 flex-col lg:h-[calc(100vh-11.5rem)]"
    >
      <DispatcherOpsShell className="flex min-h-0 flex-1 flex-col lg:overflow-hidden lg:min-h-0">
        <div className="flex w-full flex-col gap-2 py-2 sm:py-4 lg:min-h-0 lg:flex-1 lg:gap-3 lg:overflow-hidden lg:py-2">
          {isLoadingDetail ? (
            <IncidentCommandSkeleton />
          ) : loadError ? (
            <div className="rounded-xl border border-[#B91C1C]/25 bg-[#FEF2F2] p-6 text-center shadow-sm">
              <h2 className="font-semibold text-[#991B1B]">
                Unable to load incident command
              </h2>
              <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-[#991B1B]">
                {loadError}
              </p>
              <div className="mt-4 flex flex-wrap justify-center gap-2">
                <Button
                  type="button"
                  variant="secondary"
                  size="sm"
                  onClick={() => void loadDetail()}
                >
                  Retry
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  onClick={goToActiveIncidents}
                >
                  Back to Active Incidents
                </Button>
              </div>
            </div>
          ) : detail ? (
            <div className="flex min-h-0 flex-1 flex-col gap-2 lg:gap-3 lg:overflow-hidden">
              <IncidentCommandHeader
                isTerminalIncident={isTerminalIncident(detail.status)}
                onResolve={() => setResolveDialogOpen(true)}
                onClose={() => setCloseDialogOpen(true)}
                onCancel={() => setCancelDialogOpen(true)}
                onAttachToDisaster={() => setAttachDisasterDialogOpen(true)}
              />
              <IncidentCommandWorkspace
                detail={detail}
                incidentPublicUuid={incidentPublicUuid}
                opsMutationGeneration={opsMutationGeneration}
                canEditLocation={canEditLocation}
                onOpenDetails={() => setDetailsDrawerOpen(true)}
                onEditLocation={handleEditLocation}
                onAssignAgency={() => setAssignAgencyOpen(true)}
                onDispatchUnit={() => setDispatchUnitOpen(true)}
                onDispatchStatusAction={(dispatch, targetStatus) =>
                  setDispatchStatusAction({ dispatch, targetStatus })
                }
                onRefreshDetail={refreshDetail}
                onViewReportDetails={handleViewLinkedReportDetails}
                onReportUnlinked={handleReportUnlinked}
              />
            </div>
          ) : null}
        </div>
      </DispatcherOpsShell>

      {detail ? (
        <>
          <IncidentCommandDetailsDrawer
            open={detailsDrawerOpen}
            onClose={() => setDetailsDrawerOpen(false)}
            detail={detail}
            sourceLabel={sourceLabel}
            canEditLocation={canEditLocation}
            onEditLocation={handleEditLocation}
            onViewLocationHistory={handleViewLocationHistory}
          />
          <IntakeReportDetailsDrawer
            open={intakeReportDrawer != null}
            onOpenChange={handleIntakeReportDrawerOpenChange}
            reportPublicUuid={intakeReportDrawer?.reportPublicUuid ?? null}
            context="incident-command"
            linkContext={intakeReportDrawer?.linkContext ?? null}
          />
          <EditReportedLocationDialog
            open={locationDialogOpen}
            item={locationEditItem}
            dialogTitle="Edit Location"
            currentLocationLabel="Current location:"
            successMessage="Location updated."
            onClose={() => setLocationDialogOpen(false)}
            onSuccess={refreshAfterLocationUpdate}
          />
          <ReportedLocationHistoryDialog
            key={historyRefreshKey}
            open={historyDialogOpen}
            reportPublicUuid={locationSourceReportUuid}
            reportSummary={locationSourceReport?.summary}
            title="Location History"
            onClose={() => setHistoryDialogOpen(false)}
          />
          <AssignParticipatingAgencyDialog
            open={assignAgencyOpen}
            incidentPublicUuid={incidentPublicUuid}
            incidentTitle={detail.title}
            participatingAgencyUuids={participatingAgencyUuids}
            hasLeadAgency={hasLeadAgency}
            onClose={() => setAssignAgencyOpen(false)}
            onSuccess={refreshDetailAfterOpsMutation}
          />
          <DispatchUnitDialog
            open={dispatchUnitOpen}
            incidentPublicUuid={incidentPublicUuid}
            incidentTitle={detail.title}
            onClose={() => setDispatchUnitOpen(false)}
            onSuccess={refreshDetailAfterOpsMutation}
          />
          <DispatchStatusActionDialog
            open={Boolean(dispatchStatusAction)}
            dispatch={dispatchStatusAction?.dispatch ?? null}
            targetStatus={dispatchStatusAction?.targetStatus ?? null}
            onClose={() => setDispatchStatusAction(null)}
            onSuccess={refreshDetailAfterOpsMutation}
          />
          <ResolveIncidentDialog
            open={resolveDialogOpen}
            incidentPublicUuid={incidentPublicUuid}
            onClose={() => setResolveDialogOpen(false)}
            onSuccess={refreshDetail}
          />
          <CloseIncidentDialog
            open={closeDialogOpen}
            incidentPublicUuid={incidentPublicUuid}
            onClose={() => setCloseDialogOpen(false)}
            onSuccess={refreshDetail}
          />
          <CancelIncidentDialog
            open={cancelDialogOpen}
            incidentPublicUuid={incidentPublicUuid}
            onClose={() => setCancelDialogOpen(false)}
            onSuccess={refreshDetail}
          />
          <AttachIncidentToDisasterDialog
            open={attachDisasterDialogOpen}
            incidentPublicUuid={incidentPublicUuid}
            onClose={() => setAttachDisasterDialogOpen(false)}
            onSuccess={refreshDetail}
          />
        </>
      ) : null}
    </DashboardLayout>
  );
}
