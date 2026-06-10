"use client";

import Link from "next/link";
import { useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import { DisasterAffectedAreasTab } from "@/components/admin/disasters/detail/DisasterAffectedAreasTab";
import { DisasterIncidentsTab } from "@/components/admin/disasters/detail/DisasterIncidentsTab";
import { DisasterOverviewTab } from "@/components/admin/disasters/detail/DisasterOverviewTab";
import { DisasterReliefHubsNetworkTab } from "@/components/admin/disasters/detail/DisasterReliefHubsNetworkTab";
import { DisasterReliefTab } from "@/components/admin/disasters/detail/DisasterReliefTab";
import { DisasterResponsibilitiesTab } from "@/components/admin/disasters/detail/DisasterResponsibilitiesTab";
import { DisasterShelterNetworkTab } from "@/components/admin/disasters/detail/DisasterShelterNetworkTab";
import { DisasterStatusActionDialog } from "@/components/admin/disasters/detail/DisasterStatusActionDialog";
import { DisasterSupportFacilitiesTab } from "@/components/admin/disasters/detail/DisasterSupportFacilitiesTab";
import {
  computeDisasterDetailTabCounts,
  DisasterDetailTabNav,
} from "@/components/admin/disasters/detail/DisasterDetailTabNav";
import { DisasterTimelineTab } from "@/components/admin/disasters/detail/DisasterTimelineTab";
import { DeclarationAmendmentModal } from "@/components/admin/disasters/detail/DeclarationAmendmentModal";
import type { DisasterDetailTab } from "@/components/admin/disasters/detail/disasterDetailTabs";
import { useDisasterDashboard } from "@/components/admin/disasters/detail/useDisasterDashboard";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { nationalDisasterLandingPath } from "@/lib/admin-national-disaster-routes";
import {
  formatDisasterEventTypeLabel,
  formatDisasterSeverityLabel,
  formatDisasterStatusLabel,
  getAvailableLifecycleActions,
  hasInitialDeclaration,
  type DisasterLifecycleAction,
} from "@/lib/disaster-operations-format";
import type { AdminFacilityListItem } from "@/types/admin-facility";
import type { DisasterDashboardResponse } from "@/types/disaster-operations";

type DisasterDetailWorkspaceProps = {
  disasterPublicUuid: string;
};

type DisasterDetailTabPanelProps = {
  activeTab: DisasterDetailTab;
  disasterPublicUuid: string;
  dashboard: DisasterDashboardResponse;
  facilities: AdminFacilityListItem[];
  facilityLocations: ReturnType<typeof useDisasterDashboard>["facilityLocations"];
  isReadOnly: boolean;
  onRefresh: () => Promise<void>;
};

function DisasterDetailTabPanel({
  activeTab,
  disasterPublicUuid,
  dashboard,
  facilities,
  facilityLocations,
  isReadOnly,
  onRefresh,
}: DisasterDetailTabPanelProps) {
  switch (activeTab) {
    case "overview":
      return <DisasterOverviewTab dashboard={dashboard} />;
    case "affected-areas":
      return (
        <DisasterAffectedAreasTab
          disasterPublicUuid={disasterPublicUuid}
          dashboard={dashboard}
          isReadOnly={isReadOnly}
          onRefresh={onRefresh}
        />
      );
    case "shelter-network":
      return (
        <DisasterShelterNetworkTab
          disasterPublicUuid={disasterPublicUuid}
          dashboard={dashboard}
          facilities={facilities}
          facilityLocations={facilityLocations}
          isReadOnly={isReadOnly}
          onRefresh={onRefresh}
        />
      );
    case "relief-hubs":
      return (
        <DisasterReliefHubsNetworkTab
          disasterPublicUuid={disasterPublicUuid}
          dashboard={dashboard}
          facilities={facilities}
          facilityLocations={facilityLocations}
          isReadOnly={isReadOnly}
          onRefresh={onRefresh}
        />
      );
    case "support-facilities":
      return (
        <DisasterSupportFacilitiesTab
          dashboard={dashboard}
          facilities={facilities}
        />
      );
    case "agencies":
      return (
        <DisasterResponsibilitiesTab
          disasterPublicUuid={disasterPublicUuid}
          dashboard={dashboard}
          isReadOnly={isReadOnly}
          onRefresh={onRefresh}
        />
      );
    case "incidents":
      return (
        <DisasterIncidentsTab
          disasterPublicUuid={disasterPublicUuid}
          dashboard={dashboard}
          isReadOnly={isReadOnly}
          onRefresh={onRefresh}
        />
      );
    case "relief":
      return (
        <DisasterReliefTab
          disasterPublicUuid={disasterPublicUuid}
          dashboard={dashboard}
          isReadOnly={isReadOnly}
          onRefresh={onRefresh}
        />
      );
    case "timeline":
      return (
        <DisasterTimelineTab
          disasterPublicUuid={disasterPublicUuid}
          dashboard={dashboard}
          isReadOnly={isReadOnly}
          onRefresh={onRefresh}
        />
      );
    default:
      return null;
  }
}

export function DisasterDetailWorkspace({
  disasterPublicUuid,
}: DisasterDetailWorkspaceProps) {
  const {
    dashboard,
    facilities,
    facilityLocations,
    isLoading,
    isRefreshing,
    error,
    isReadOnly,
    refresh,
  } = useDisasterDashboard(disasterPublicUuid);

  const [activeTab, setActiveTab] = useState<DisasterDetailTab>("overview");
  const [lifecycleAction, setLifecycleAction] =
    useState<DisasterLifecycleAction | null>(null);
  const [amendOpen, setAmendOpen] = useState(false);

  const tabCounts = useMemo(
    () =>
      dashboard
        ? computeDisasterDetailTabCounts(dashboard, facilities)
        : {},
    [dashboard, facilities],
  );

  if (isLoading && !dashboard) {
    return <LoadingSkeleton lines={10} />;
  }

  if (error && !dashboard) {
    return (
      <div className="space-y-4">
        <Link
          href={nationalDisasterLandingPath()}
          className="text-sm font-medium text-[#002D62] hover:underline"
        >
          ← Disaster Command
        </Link>
        <ErrorAlert message={error} />
      </div>
    );
  }

  if (!dashboard) return null;

  const { disaster } = dashboard;
  const lifecycleActions = getAvailableLifecycleActions(disaster.status_code);
  const canAmend =
    !isReadOnly && hasInitialDeclaration(dashboard.declarations ?? []);

  const handleRefresh = async () => {
    await refresh();
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2 overflow-x-hidden lg:overflow-hidden">
      <div className="shrink-0 space-y-0.5">
        <Link
          href={nationalDisasterLandingPath()}
          className="text-sm font-medium text-[#002D62] hover:underline"
        >
          ← Disaster Command
        </Link>

        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-lg font-semibold text-slate-900">
                {disaster.title}
              </h2>
              <Badge size="compact" tone="active">
                {formatBadgeLabel(formatDisasterStatusLabel(disaster.status_code))}
              </Badge>
              {isReadOnly ? (
                <span className="text-xs text-slate-500">Read-only</span>
              ) : null}
            </div>
            <p className="mt-0.5 truncate text-sm text-slate-600">
              {disaster.event_code}
              {" · "}
              {formatDisasterEventTypeLabel(
                disaster.event_type_code,
                disaster.event_type_name,
              )}
              {disaster.severity_level
                ? ` · ${formatDisasterSeverityLabel(disaster.severity_level)}`
                : ""}
            </p>
          </div>
          <div className="flex shrink-0 flex-wrap items-center justify-end gap-2">
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={() => void handleRefresh()}
              disabled={isRefreshing}
              aria-label="Refresh disaster dashboard"
              className="px-2 sm:px-3"
            >
              <RefreshCw
                className={`h-4 w-4 ${isRefreshing ? "animate-spin" : ""}`}
                aria-hidden
              />
              <span className="sr-only sm:not-sr-only sm:ml-1.5">Refresh</span>
            </Button>
            {!isReadOnly && canAmend ? (
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setAmendOpen(true)}
              >
                Amend Declaration
              </Button>
            ) : null}
            {!isReadOnly && lifecycleActions.includes("resolve") ? (
              <Button
                type="button"
                size="sm"
                onClick={() => setLifecycleAction("resolve")}
              >
                Resolve
              </Button>
            ) : null}
            {!isReadOnly && lifecycleActions.includes("close") ? (
              <Button
                type="button"
                size="sm"
                onClick={() => setLifecycleAction("close")}
              >
                Close
              </Button>
            ) : null}
            {!isReadOnly && lifecycleActions.includes("cancel") ? (
              <Button
                type="button"
                variant="danger"
                size="sm"
                onClick={() => setLifecycleAction("cancel")}
              >
                Cancel
              </Button>
            ) : null}
          </div>
        </div>
      </div>

      <section
        aria-label="Disaster dashboard"
        className="flex min-h-0 flex-1 flex-col rounded-xl border border-slate-200/80 bg-white shadow-sm lg:overflow-hidden"
      >
        <div className="shrink-0 border-b border-slate-100 px-3 py-2.5 lg:hidden">
          <DisasterDetailTabNav
            activeTab={activeTab}
            onSelect={setActiveTab}
            tabCounts={tabCounts}
            layout="horizontal"
          />
        </div>

        <div className="flex min-h-0 flex-1 flex-col lg:grid lg:grid-cols-[minmax(12rem,14rem)_minmax(0,1fr)] lg:overflow-hidden">
          <div className="hidden min-h-0 shrink-0 border-slate-100 lg:block lg:border-r lg:overflow-y-auto lg:overscroll-y-contain">
            <DisasterDetailTabNav
              activeTab={activeTab}
              onSelect={setActiveTab}
              tabCounts={tabCounts}
              layout="vertical"
            />
          </div>

          <div
            className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain p-3 lg:p-4"
            role="tabpanel"
            aria-label={`${activeTab} section`}
          >
            <DisasterDetailTabPanel
              activeTab={activeTab}
              disasterPublicUuid={disasterPublicUuid}
              dashboard={dashboard}
              facilities={facilities}
              facilityLocations={facilityLocations}
              isReadOnly={isReadOnly}
              onRefresh={handleRefresh}
            />
          </div>
        </div>
      </section>

      {lifecycleAction ? (
        <DisasterStatusActionDialog
          open
          action={lifecycleAction}
          disasterPublicUuid={disasterPublicUuid}
          onClose={() => setLifecycleAction(null)}
          onSuccess={handleRefresh}
        />
      ) : null}

      <DeclarationAmendmentModal
        open={amendOpen}
        disasterPublicUuid={disasterPublicUuid}
        onClose={() => setAmendOpen(false)}
        onSuccess={handleRefresh}
      />
    </div>
  );
}
