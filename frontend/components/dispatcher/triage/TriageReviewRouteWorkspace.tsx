"use client";

import { useEffect } from "react";
import { X } from "lucide-react";
import { EditReportedLocationDialog } from "@/components/dispatcher/triage/EditReportedLocationDialog";
import { ReportedLocationHistoryDialog } from "@/components/dispatcher/triage/ReportedLocationHistoryDialog";
import { ReviewRoutePanel } from "@/components/dispatcher/triage/ReviewRoutePanel";
import { useTriageReviewRoute } from "@/components/dispatcher/triage/useTriageReviewRoute";
import type { RouteMode } from "@/components/dispatcher/triage/types";

export type TriageReviewRouteWorkspaceProps = {
  reportId: string | null;
  enabled: boolean;
  queueEmpty?: boolean;
  showPanelHeader?: boolean;
  continueLabel?: string;
  continueAfterSuccess: "advance-queue" | "close";
  onAfterRouteSuccess?: () => void | Promise<void>;
  onAfterLocationUpdate?: () => void | Promise<void>;
  onRequestClose?: () => void;
  onContinueAdvanceQueue?: () => void | Promise<void>;
  className?: string;
  embedded?: boolean;
  variant?: "panel" | "drawer";
  onWorkflowStateChange?: (state: { isSuccessMode: boolean; routeMode: RouteMode }) => void;
};

export function TriageReviewRouteWorkspace({
  reportId,
  enabled,
  queueEmpty = false,
  showPanelHeader = true,
  continueLabel,
  continueAfterSuccess,
  onAfterRouteSuccess,
  onAfterLocationUpdate,
  onRequestClose,
  onContinueAdvanceQueue,
  className,
  embedded = false,
  variant = "panel",
  onWorkflowStateChange,
}: TriageReviewRouteWorkspaceProps) {
  const reviewRoute = useTriageReviewRoute({
    reportId,
    enabled,
    onAfterRouteSuccess,
    onAfterLocationUpdate,
  });

  const handleContinueAfterSuccess = async () => {
    if (continueAfterSuccess === "close") {
      reviewRoute.clearSuccessAndResetOptions();
      onRequestClose?.();
      return;
    }
    reviewRoute.clearSuccessAndResetOptions();
    await onContinueAdvanceQueue?.();
  };

  useEffect(() => {
    onWorkflowStateChange?.({
      isSuccessMode: reviewRoute.isSuccessRouteMode,
      routeMode: reviewRoute.routeMode,
    });
  }, [
    onWorkflowStateChange,
    reviewRoute.isSuccessRouteMode,
    reviewRoute.routeMode,
  ]);

  const panelClassName = embedded
    ? `flex h-full min-h-0 w-full min-w-0 flex-col ${className ?? ""}`
    : `flex min-w-0 flex-col ${className ?? ""}`;

  const headerSubtitle =
    reviewRoute.displayItem?.reportCode?.trim() ||
    reviewRoute.displayItem?.summary?.trim() ||
    null;

  return (
    <>
      <div className={panelClassName}>
        {variant === "drawer" ? (
          <div className="flex shrink-0 items-start justify-between gap-3 border-b border-slate-200 px-4 py-4 sm:px-5">
            <div className="min-w-0">
              <h2 className="text-sm font-semibold text-slate-900">
                Review & Route
              </h2>
              {headerSubtitle ? (
                <p className="mt-0.5 truncate text-xs text-slate-500">
                  {headerSubtitle}
                </p>
              ) : null}
            </div>
            <button
              type="button"
              onClick={onRequestClose}
              className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-slate-200 text-slate-600 transition-colors hover:bg-slate-50"
              aria-label="Close review and route"
            >
              <X className="h-5 w-5" aria-hidden />
            </button>
          </div>
        ) : null}

        <div
          className={
            variant === "drawer"
              ? "min-h-0 flex-1 overflow-hidden"
              : "lg:overflow-hidden"
          }
        >
          <ReviewRoutePanel
          item={reviewRoute.selectedDetail}
          handoffItem={reviewRoute.handoffItem}
          routeMode={reviewRoute.routeMode}
          queueEmpty={queueEmpty}
          detailLoading={reviewRoute.detailLoading}
          detailError={reviewRoute.detailError}
          serviceCaseDraft={reviewRoute.serviceCaseDraft}
          emergencyDraft={reviewRoute.emergencyDraft}
          linkDraft={reviewRoute.linkDraft}
          routeResult={reviewRoute.routeResult}
          routeError={reviewRoute.routeError}
          submittingRoute={reviewRoute.submittingRoute}
          activeIncidents={reviewRoute.activeIncidents}
          incidentsLoading={reviewRoute.incidentsLoading}
          incidentsError={reviewRoute.incidentsError}
          onRetryIncidents={() => void reviewRoute.loadActiveIncidents()}
          onServiceCaseDraftChange={reviewRoute.setServiceCaseDraft}
          onEmergencyDraftChange={reviewRoute.setEmergencyDraft}
          onLinkDraftChange={reviewRoute.setLinkDraft}
          onSelectRoute={reviewRoute.handleSelectRoute}
          onBackToOptions={reviewRoute.handleBackToOptions}
          onSubmitServiceCase={() => void reviewRoute.handleSubmitServiceCase()}
          onSubmitEmergency={() => void reviewRoute.handleSubmitEmergency()}
          onSubmitLink={() => void reviewRoute.handleSubmitLink()}
          onContinueTriage={() => void handleContinueAfterSuccess()}
          onEditLocation={() => reviewRoute.setLocationDialogOpen(true)}
          onViewHistory={() => reviewRoute.setHistoryDialogOpen(true)}
          onOpenDetail={reviewRoute.handleOpenDetail}
          showHeader={showPanelHeader}
          continueLabel={continueLabel}
          selectedDisasterPublicUuid={reviewRoute.selectedDisasterPublicUuid}
          onDisasterChange={reviewRoute.setSelectedDisasterPublicUuid}
        />
        </div>
      </div>

      <EditReportedLocationDialog
        open={reviewRoute.locationDialogOpen}
        item={reviewRoute.locationDialogItem}
        onClose={() => reviewRoute.setLocationDialogOpen(false)}
        onSuccess={() => void reviewRoute.refreshAfterLocationUpdate()}
      />

      <ReportedLocationHistoryDialog
        open={reviewRoute.historyDialogOpen}
        reportPublicUuid={reviewRoute.locationDialogItem?.id ?? null}
        reportSummary={reviewRoute.locationDialogItem?.summary}
        onClose={() => reviewRoute.setHistoryDialogOpen(false)}
      />
    </>
  );
}
