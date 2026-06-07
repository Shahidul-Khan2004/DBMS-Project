"use client";

import { useEffect, useState } from "react";
import { EmergencyIncidentRouteForm } from "@/components/dispatcher/triage/EmergencyIncidentRouteForm";
import { ExistingIncidentRouteForm } from "@/components/dispatcher/triage/ExistingIncidentRouteForm";
import { DismissRouteForm } from "@/components/dispatcher/triage/DismissRouteForm";
import { ReportedLocationDisplay } from "@/components/dispatcher/triage/ReportedLocationDisplay";
import { hasValidReportedLocation } from "@/components/dispatcher/triage/reportedLocationCoords";
import { RouteSelector } from "@/components/dispatcher/triage/RouteSelector";
import { RouteSuccessHandoff } from "@/components/dispatcher/triage/RouteSuccessHandoff";
import { SelectedIntakeHeader } from "@/components/dispatcher/triage/SelectedIntakeHeader";
import { ServiceCaseRouteForm } from "@/components/dispatcher/triage/ServiceCaseRouteForm";
import { WorkflowContextHeader } from "@/components/dispatcher/triage/WorkflowContextHeader";
import { DisasterLinkSelector } from "@/components/dispatcher/disasters/DisasterLinkSelector";
import { ReporterReliabilityCard } from "@/components/dispatcher/triage/ReporterReliabilityCard";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { Button } from "@/components/ui/Button";
import type {
  ActiveIncidentOption,
  DismissDraft,
  EmergencyDraft,
  IntakeQueueItem,
  LinkDraft,
  RouteMode,
  RouteResult,
  ServiceCaseDraft,
} from "@/components/dispatcher/triage/types";
import type { RouteChoice } from "@/components/dispatcher/triage/triageReviewRouteUtils";

interface ReviewRoutePanelProps {
  item: IntakeQueueItem | null;
  handoffItem: IntakeQueueItem | null;
  routeMode: RouteMode;
  queueEmpty: boolean;
  detailLoading?: boolean;
  detailError?: string | null;
  serviceCaseDraft: ServiceCaseDraft;
  emergencyDraft: EmergencyDraft;
  linkDraft: LinkDraft;
  dismissDraft: DismissDraft;
  routeResult: RouteResult | null;
  routeError?: string | null;
  submittingRoute?: "service_case" | "emergency" | "link" | "duplicate" | "false_report" | null;
  activeIncidents?: ActiveIncidentOption[];
  incidentsLoading?: boolean;
  incidentsError?: string | null;
  onRetryIncidents?: () => void;
  onServiceCaseDraftChange: (draft: ServiceCaseDraft) => void;
  onEmergencyDraftChange: (draft: EmergencyDraft) => void;
  onLinkDraftChange: (draft: LinkDraft) => void;
  onDismissDraftChange: (draft: DismissDraft) => void;
  onSelectRoute: (mode: RouteChoice) => void;
  onBackToOptions: () => void;
  onSubmitServiceCase: () => void;
  onSubmitEmergency: () => void;
  onSubmitLink: () => void;
  onSubmitDismiss: () => void;
  onContinueTriage: () => void;
  onEditLocation: () => void;
  onViewHistory: () => void;
  onOpenDetail: () => void;
  showHeader?: boolean;
  continueLabel?: string;
  selectedDisasterPublicUuid?: string | null;
  onDisasterChange?: (uuid: string | null) => void;
  showDisasterRoute?: boolean;
  onOpenDisasterDialog?: () => void;
  disasterRouteDisabled?: boolean;
  embedded?: boolean;
  reporterRisk?: import("@/types/reporter-risk").ReporterRiskSummary | null;
  reporterRiskLoading?: boolean;
  onRecordVerification?: () => void;
}

function isFormRouteMode(mode: RouteMode): boolean {
  return (
    mode === "service_case" ||
    mode === "emergency_incident" ||
    mode === "existing_incident" ||
    mode === "duplicate" ||
    mode === "false_report"
  );
}

function LocationRequiredNotice({ onEditLocation }: { onEditLocation: () => void }) {
  return (
    <div className="rounded-lg border border-amber-200 bg-amber-50/80 px-3 py-2 text-sm text-amber-950">
      <p>A reported location is required before this report can be routed.</p>
      <Button
        type="button"
        variant="secondary"
        size="sm"
        className="mt-1.5"
        onClick={onEditLocation}
      >
        Edit Location
      </Button>
    </div>
  );
}

function OriginalDescriptionSection({ description }: { description: string }) {
  const [expanded, setExpanded] = useState(false);
  const isLong = description.length > 180 || description.split("\n").length > 3;

  return (
    <section>
      <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
        Original Description
      </h4>
      <p
        className={`mt-1 text-sm leading-snug text-slate-700 ${
          !expanded && isLong ? "line-clamp-3" : ""
        }`}
      >
        {description}
      </p>
      {isLong ? (
        <button
          type="button"
          onClick={() => setExpanded((open) => !open)}
          className="mt-1 text-xs font-medium text-[#002D62] hover:underline"
        >
          {expanded ? "Show less" : "View full description"}
        </button>
      ) : null}
    </section>
  );
}

function IntakeReportDetailsCollapsible({
  item,
  onEditLocation,
  onViewHistory,
}: {
  item: IntakeQueueItem;
  onEditLocation: () => void;
  onViewHistory: () => void;
}) {
  return (
    <div className="space-y-3 rounded-lg border border-slate-100 bg-slate-50/60 p-3">
      <ReportedLocationDisplay
        compact
        location={item.location}
        previewKey={item.id}
        onEditLocation={onEditLocation}
        onViewHistory={onViewHistory}
      />
      <OriginalDescriptionSection description={item.description} />
    </div>
  );
}

export function ReviewRoutePanel({
  item,
  handoffItem,
  routeMode,
  queueEmpty,
  detailLoading = false,
  detailError = null,
  serviceCaseDraft,
  emergencyDraft,
  linkDraft,
  dismissDraft,
  routeResult,
  routeError = null,
  submittingRoute = null,
  activeIncidents = [],
  incidentsLoading = false,
  incidentsError = null,
  onRetryIncidents,
  onServiceCaseDraftChange,
  onEmergencyDraftChange,
  onLinkDraftChange,
  onDismissDraftChange,
  onSelectRoute,
  onBackToOptions,
  onSubmitServiceCase,
  onSubmitEmergency,
  onSubmitLink,
  onSubmitDismiss,
  onContinueTriage,
  onEditLocation,
  onViewHistory,
  onOpenDetail,
  showHeader = true,
  continueLabel,
  selectedDisasterPublicUuid = null,
  onDisasterChange,
  showDisasterRoute = false,
  onOpenDisasterDialog,
  disasterRouteDisabled = false,
  embedded = false,
  reporterRisk = null,
  reporterRiskLoading = false,
  onRecordVerification,
}: ReviewRoutePanelProps) {
  const [detailsExpanded, setDetailsExpanded] = useState(false);

  const displayItem = handoffItem ?? item;
  const locationMissing = displayItem
    ? !hasValidReportedLocation(displayItem.location)
    : false;
  const routeSubmitDisabled = locationMissing;

  const isSuccessMode =
    routeMode === "success_service_case" ||
    routeMode === "success_emergency_incident" ||
    routeMode === "success_existing_incident" ||
    routeMode === "success_duplicate" ||
    routeMode === "success_false_report";

  const isFormMode = isFormRouteMode(routeMode);
  const isDefaultReview = routeMode === "options";

  const formRouteError =
    routeMode === "service_case" ||
    routeMode === "emergency_incident" ||
    routeMode === "existing_incident" ||
    routeMode === "duplicate" ||
    routeMode === "false_report"
      ? routeError
      : null;

  useEffect(() => {
    if (isFormMode) {
      setDetailsExpanded(false);
    }
  }, [displayItem?.id, routeMode, isFormMode]);

  const showContextHeader =
    Boolean(displayItem) &&
    !detailLoading &&
    !detailError &&
    (isDefaultReview || isFormMode || isSuccessMode);

  const showFixedHeader = showHeader || showContextHeader;

  const scrollBodyClassName = embedded
    ? "min-h-0 flex-1 space-y-3 overflow-y-auto overscroll-y-contain px-5 py-4 pb-6"
    : "min-h-0 flex-1 space-y-3 px-5 py-4 pb-6 lg:overflow-y-auto lg:overscroll-y-contain";

  return (
    <section className="flex h-full min-h-0 w-full min-w-0 flex-col overflow-hidden rounded-xl border border-slate-200/90 bg-white shadow-sm">
      {showFixedHeader ? (
        <header className="shrink-0 space-y-3 border-b border-slate-100 px-5 py-4">
          {showHeader ? (
            <h3 className="text-sm font-semibold text-slate-900">Review & Route</h3>
          ) : null}

          {showContextHeader && displayItem && isDefaultReview ? (
            <>
              <SelectedIntakeHeader item={displayItem} />

              {locationMissing ? (
                <LocationRequiredNotice onEditLocation={onEditLocation} />
              ) : null}

              <RouteSelector
                routeMode={routeMode}
                onSelect={onSelectRoute}
                showDismissRoutes
                showDisasterRoute={showDisasterRoute}
                onOpenDisasterDialog={onOpenDisasterDialog}
                disasterRouteDisabled={disasterRouteDisabled}
              />
            </>
          ) : null}

          {showContextHeader && displayItem && isFormMode ? (
            <WorkflowContextHeader
              item={displayItem}
              detailsExpanded={detailsExpanded}
              onToggleDetails={() => setDetailsExpanded((open) => !open)}
              onBackToRouteOptions={onBackToOptions}
            />
          ) : null}

          {showContextHeader && displayItem && isSuccessMode ? (
            <WorkflowContextHeader
              item={displayItem}
              detailsExpanded={false}
              onToggleDetails={() => {}}
              onBackToRouteOptions={onContinueTriage}
              showActions={false}
            />
          ) : null}
        </header>
      ) : null}

      <div className={scrollBodyClassName}>
        {!displayItem && !isSuccessMode ? (
          <div className="py-6 text-center text-sm text-slate-500">
            {queueEmpty ? (
              <>
                <p className="font-medium text-slate-700">No intake selected</p>
                <p className="mt-1">
                  New pending reports will appear here for review.
                </p>
              </>
            ) : (
              <p>Select a pending report to review and route.</p>
            )}
          </div>
        ) : detailLoading && !isSuccessMode ? (
          <LoadingSkeleton lines={4} />
        ) : detailError && !isSuccessMode ? (
          <ErrorAlert message={detailError} />
        ) : displayItem ? (
          <>
            {isDefaultReview ? (
              <>
                <ReporterReliabilityCard
                  reporterRisk={reporterRisk}
                  loading={reporterRiskLoading}
                  onRecordVerification={onRecordVerification}
                />

                <ReportedLocationDisplay
                  location={displayItem.location}
                  previewKey={displayItem.id}
                  onEditLocation={onEditLocation}
                  onViewHistory={onViewHistory}
                />

                <OriginalDescriptionSection description={displayItem.description} />
              </>
            ) : null}

            {isFormMode ? (
              <div className="space-y-3">
                {locationMissing ? (
                  <LocationRequiredNotice onEditLocation={onEditLocation} />
                ) : null}

                {detailsExpanded ? (
                  <IntakeReportDetailsCollapsible
                    item={displayItem}
                    onEditLocation={onEditLocation}
                    onViewHistory={onViewHistory}
                  />
                ) : null}

                {routeMode === "service_case" ? (
                  <ServiceCaseRouteForm
                    draft={serviceCaseDraft}
                    onChange={onServiceCaseDraftChange}
                    onSubmit={onSubmitServiceCase}
                    submitError={formRouteError}
                    isSubmitting={submittingRoute === "service_case"}
                    submitDisabled={routeSubmitDisabled}
                  />
                ) : null}

                {routeMode === "emergency_incident" ? (
                  <>
                    <EmergencyIncidentRouteForm
                      item={displayItem}
                      draft={emergencyDraft}
                      onChange={onEmergencyDraftChange}
                      onSubmit={onSubmitEmergency}
                      onEditReportedLocation={onEditLocation}
                      submitError={formRouteError}
                      isSubmitting={submittingRoute === "emergency"}
                      submitDisabled={routeSubmitDisabled}
                    />
                    {onDisasterChange ? (
                      <DisasterLinkSelector
                        selectedDisasterPublicUuid={selectedDisasterPublicUuid}
                        onChange={onDisasterChange}
                        disabled={
                          submittingRoute === "emergency" || routeSubmitDisabled
                        }
                      />
                    ) : null}
                  </>
                ) : null}

                {routeMode === "existing_incident" ? (
                  <ExistingIncidentRouteForm
                    intakeLocation={displayItem.location}
                    draft={linkDraft}
                    incidents={activeIncidents}
                    incidentsLoading={incidentsLoading}
                    incidentsError={incidentsError}
                    onRetryIncidents={onRetryIncidents}
                    onChange={onLinkDraftChange}
                    onSubmit={onSubmitLink}
                    submitError={formRouteError}
                    isSubmitting={submittingRoute === "link"}
                    submitDisabled={routeSubmitDisabled}
                  />
                ) : null}

                {routeMode === "existing_incident" && onDisasterChange ? (
                  <DisasterLinkSelector
                    selectedDisasterPublicUuid={selectedDisasterPublicUuid}
                    onChange={onDisasterChange}
                    disabled={submittingRoute === "link" || routeSubmitDisabled}
                  />
                ) : null}

                {routeMode === "duplicate" || routeMode === "false_report" ? (
                  <DismissRouteForm
                    disposition={routeMode}
                    draft={dismissDraft}
                    onChange={onDismissDraftChange}
                    onSubmit={onSubmitDismiss}
                    submitError={formRouteError}
                    isSubmitting={submittingRoute === routeMode}
                  />
                ) : null}
              </div>
            ) : null}

            {isSuccessMode && routeResult ? (
              <RouteSuccessHandoff
                item={displayItem}
                routeResult={routeResult}
                onOpenDetail={onOpenDetail}
                onContinueTriage={onContinueTriage}
                continueLabel={continueLabel}
              />
            ) : null}
          </>
        ) : null}
      </div>
    </section>
  );
}
