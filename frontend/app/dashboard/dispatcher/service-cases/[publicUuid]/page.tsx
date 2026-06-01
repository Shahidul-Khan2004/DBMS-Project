"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { toast } from "sonner";
import { DashboardLayout } from "@/components/dashboard/DashboardLayout";
import { IntakeReportDetailsDrawer } from "@/components/dispatcher/intake";
import { DispatcherOpsShell } from "@/components/dispatcher/DispatcherOpsShell";
import {
  canSendDispatcherCitizenMessage,
  EscalateCaseDialog,
  overflowActionLabel,
  overflowActionToStatusTarget,
  primaryActionLabel,
  primaryActionOpensMessageDialog,
  primaryActionToStatusTarget,
  ResolveCaseDialog,
  resumeInternalReviewDialogCopy,
  SendResponseDialog,
  ServiceCaseCommandBar,
  ServiceCaseDetailSkeleton,
  ServiceCaseStatusActionDialog,
  ServiceCaseWorkspace,
  startReviewDialogDescription,
  statusActionDialogDescription,
  type ServiceCaseOverflowAction,
  type ServiceCasePrimaryAction,
  type ServiceCaseStatusActionTarget,
} from "@/components/dispatcher/service-cases/detail";
import { Button } from "@/components/ui/Button";
import { EmptyState, PageLoading } from "@/components/ui/StatusState";
import { ApiError, ensureAuthSession } from "@/lib/api";
import { clearAuthSession } from "@/lib/auth-store";
import {
  DISPATCHER_DASHBOARD_SUBTITLE,
  DISPATCHER_DASHBOARD_TITLE,
} from "@/lib/dispatcher-dashboard";
import { getOperationsServiceCaseDetail } from "@/lib/service-case-api";
import { useDispatcherWorkspaceGuard } from "@/lib/use-dispatcher-workspace-guard";
import type { ServiceCaseDetailResponse } from "@/types/service-case";

const LOAD_ERROR_MESSAGE =
  "Service case details could not be retrieved. Try again.";

function getServiceCaseLoadErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 404) {
      return "This service case could not be found. It may have been removed or you may not have access.";
    }
    if (error.status === 0 || error.code === "NETWORK_ERROR") {
      return "Could not reach the server. Please try again.";
    }
    if (error.status === 403 || error.code === "FORBIDDEN") {
      return "You do not have permission to view this service case.";
    }
  }
  return LOAD_ERROR_MESSAGE;
}

type StatusDialogState = {
  title: string;
  confirmLabel: string;
  description: string;
  targetStatus: ServiceCaseStatusActionTarget;
};

export default function DispatcherServiceCaseDetailPage() {
  const router = useRouter();
  const params = useParams();
  const casePublicUuid =
    typeof params.publicUuid === "string" ? params.publicUuid : "";

  const isChecking = useDispatcherWorkspaceGuard("serviceCases");
  const [detail, setDetail] = useState<ServiceCaseDetailResponse | null>(null);
  const [isLoadingDetail, setIsLoadingDetail] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [linkedIncidentPublicUuid, setLinkedIncidentPublicUuid] = useState<
    string | null
  >(null);

  const [sendResponseOpen, setSendResponseOpen] = useState(false);
  const [resolveOpen, setResolveOpen] = useState(false);
  const [escalateOpen, setEscalateOpen] = useState(false);
  const [intakeDrawerOpen, setIntakeDrawerOpen] = useState(false);
  const [statusDialog, setStatusDialog] = useState<StatusDialogState | null>(
    null,
  );

  const loadDetail = useCallback(async () => {
    if (!casePublicUuid) {
      setLoadError("Invalid service case link.");
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
      const data = await getOperationsServiceCaseDetail(casePublicUuid);
      setDetail(data);
      const fromCase = data.service_case.linked_incident_public_uuid?.trim();
      if (fromCase) {
        setLinkedIncidentPublicUuid(fromCase);
      }
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Failed to load service case detail", err);
      }
      setLoadError(getServiceCaseLoadErrorMessage(err));
      setDetail(null);
    } finally {
      setIsLoadingDetail(false);
    }
  }, [casePublicUuid, router]);

  const refreshDetail = useCallback(async () => {
    if (!casePublicUuid) return;

    const accessToken = await ensureAuthSession();
    if (!accessToken) {
      router.replace("/auth/login");
      return;
    }

    setIsRefreshing(true);
    try {
      const data = await getOperationsServiceCaseDetail(casePublicUuid);
      setDetail(data);
      setLoadError(null);
      const fromCase = data.service_case.linked_incident_public_uuid?.trim();
      if (fromCase) {
        setLinkedIncidentPublicUuid(fromCase);
      }
    } catch (err) {
      if (process.env.NODE_ENV === "development") {
        console.error("Failed to refresh service case detail", err);
      }
      toast.error(getServiceCaseLoadErrorMessage(err));
    } finally {
      setIsRefreshing(false);
    }
  }, [casePublicUuid, router]);

  useEffect(() => {
    if (isChecking) return;
    void loadDetail();
  }, [isChecking, loadDetail]);

  const handleLogout = () => {
    sessionStorage.removeItem("loggedInUser");
    clearAuthSession();
    router.push("/");
  };

  const goToServiceCases = useCallback(() => {
    router.push("/dashboard/dispatcher/service-cases");
  }, [router]);

  const serviceCase = detail?.service_case ?? null;
  const canEscalate = Boolean(serviceCase?.intake_public_uuid);

  const resolvedIncidentLink = useMemo(() => {
    return (
      linkedIncidentPublicUuid ||
      serviceCase?.linked_incident_public_uuid?.trim() ||
      null
    );
  }, [linkedIncidentPublicUuid, serviceCase?.linked_incident_public_uuid]);

  const handlePrimaryAction = useCallback((action: ServiceCasePrimaryAction) => {
    if (primaryActionOpensMessageDialog(action)) {
      setSendResponseOpen(true);
      return;
    }
    if (action === "resolve") {
      setResolveOpen(true);
      return;
    }
    if (action === "escalate") {
      setEscalateOpen(true);
      return;
    }
    const target = primaryActionToStatusTarget(action);
    if (!target) return;
    setStatusDialog({
      title: primaryActionLabel(action),
      confirmLabel: primaryActionLabel(action),
      description:
        action === "start_review"
          ? startReviewDialogDescription()
          : statusActionDialogDescription(target),
      targetStatus: target,
    });
  }, []);

  const handleOverflowAction = useCallback((action: ServiceCaseOverflowAction) => {
    if (action === "resume_internal_review") {
      const copy = resumeInternalReviewDialogCopy();
      setStatusDialog({
        title: copy.title,
        confirmLabel: copy.confirmLabel,
        description: copy.description,
        targetStatus: "under_review",
      });
      return;
    }
    const target = overflowActionToStatusTarget(action);
    const label = overflowActionLabel(action);
    setStatusDialog({
      title: label,
      confirmLabel: label,
      description: statusActionDialogDescription(target),
      targetStatus: target,
    });
  }, []);

  const handleEscalateSuccess = useCallback(
    async (incidentPublicUuid: string | null) => {
      if (incidentPublicUuid) {
        setLinkedIncidentPublicUuid(incidentPublicUuid);
      }
      await refreshDetail();
    },
    [refreshDetail],
  );

  if (isChecking) {
    return <PageLoading label="Loading service case workspace" />;
  }

  return (
    <DashboardLayout
      title={DISPATCHER_DASHBOARD_TITLE}
      subtitle={DISPATCHER_DASHBOARD_SUBTITLE}
      onLogout={handleLogout}
      hideSidebar
      showHealthBadge={false}
      contentClassName="flex min-h-0 flex-col xl:h-[calc(100vh-11.5rem)]"
    >
      <DispatcherOpsShell className="flex min-h-0 flex-1 flex-col xl:h-full xl:min-h-0 xl:overflow-hidden">
        <div className="flex w-full min-h-0 flex-col gap-1 py-0 xl:flex-1 xl:min-h-0 xl:gap-1.5 xl:overflow-hidden">
          {isLoadingDetail ? (
            <ServiceCaseDetailSkeleton />
          ) : loadError ? (
            <div className="rounded-xl border border-[#B91C1C]/25 bg-[#FEF2F2] p-6 text-center shadow-sm">
              <h2 className="font-semibold text-[#991B1B]">
                Unable to load case workspace
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
                  onClick={goToServiceCases}
                >
                  Back to Service Cases
                </Button>
              </div>
            </div>
          ) : serviceCase && detail ? (
            <div className="flex min-h-0 flex-1 flex-col gap-1 xl:gap-1.5 xl:overflow-hidden">
              <ServiceCaseCommandBar
                statusCode={serviceCase.status_code}
                canEscalate={canEscalate}
                isRefreshing={isRefreshing}
                onRefresh={() => void refreshDetail()}
                onPrimaryAction={handlePrimaryAction}
                onOverflowAction={handleOverflowAction}
              />

              <ServiceCaseWorkspace
                serviceCase={serviceCase}
                messages={detail.messages}
                statusHistory={detail.status_history}
                assignments={detail.assignments}
                resolution={detail.resolution}
                linkedIncidentPublicUuid={resolvedIncidentLink}
                canViewOriginalReport={Boolean(
                  serviceCase.intake_public_uuid?.trim(),
                )}
                onViewOriginalReport={() => setIntakeDrawerOpen(true)}
                onSendResponse={() => {
                  if (canSendDispatcherCitizenMessage(serviceCase.status_code)) {
                    setSendResponseOpen(true);
                  }
                }}
              />
            </div>
          ) : (
            <EmptyState
              title="Service case not found"
              description="The requested service case could not be loaded."
              action={
                <Link
                  href="/dashboard/dispatcher/service-cases"
                  className="inline-flex text-sm font-medium text-[#006747] hover:text-[#002D62]"
                >
                  Back to Service Cases
                </Link>
              }
            />
          )}
        </div>
      </DispatcherOpsShell>

      {serviceCase ? (
        <>
          <SendResponseDialog
            open={sendResponseOpen}
            casePublicUuid={casePublicUuid}
            statusCode={serviceCase.status_code}
            onClose={() => setSendResponseOpen(false)}
            onSuccess={refreshDetail}
          />
          <ResolveCaseDialog
            open={resolveOpen}
            casePublicUuid={casePublicUuid}
            onClose={() => setResolveOpen(false)}
            onSuccess={refreshDetail}
          />
          {serviceCase.intake_public_uuid ? (
            <EscalateCaseDialog
              open={escalateOpen}
              intakePublicUuid={serviceCase.intake_public_uuid}
              defaultTitle={serviceCase.title}
              onClose={() => setEscalateOpen(false)}
              onSuccess={handleEscalateSuccess}
            />
          ) : null}
          {statusDialog ? (
            <ServiceCaseStatusActionDialog
              open
              casePublicUuid={casePublicUuid}
              title={statusDialog.title}
              description={statusDialog.description}
              targetStatus={statusDialog.targetStatus}
              confirmLabel={statusDialog.confirmLabel}
              onClose={() => setStatusDialog(null)}
              onSuccess={refreshDetail}
            />
          ) : null}
          <IntakeReportDetailsDrawer
            open={intakeDrawerOpen}
            onOpenChange={setIntakeDrawerOpen}
            reportPublicUuid={serviceCase.intake_public_uuid}
            context="command-center"
          />
        </>
      ) : null}
    </DashboardLayout>
  );
}
