"use client";

import Link from "next/link";
import { useState } from "react";
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
import { DisasterTimelineTab } from "@/components/admin/disasters/detail/DisasterTimelineTab";
import { DeclarationAmendmentModal } from "@/components/admin/disasters/detail/DeclarationAmendmentModal";
import {
  DISASTER_DETAIL_TABS,
  type DisasterDetailTab,
} from "@/components/admin/disasters/detail/disasterDetailTabs";
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

type DisasterDetailWorkspaceProps = {
  disasterPublicUuid: string;
};

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
          ← National Disaster Management
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
    <div className="flex min-h-0 flex-1 flex-col overflow-x-hidden lg:overflow-hidden">
      <div className="mb-3 shrink-0 space-y-1">
        <Link
          href={nationalDisasterLandingPath()}
          className="text-sm font-medium text-[#002D62] hover:underline"
        >
          ← National Disaster Management
        </Link>

        <div className="flex flex-wrap items-start justify-between gap-2">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <h2 className="text-xl font-semibold text-slate-900">
                {disaster.title}
              </h2>
              <Badge size="compact" tone="active">
                {formatBadgeLabel(formatDisasterStatusLabel(disaster.status_code))}
              </Badge>
              {isReadOnly ? (
                <span className="text-xs text-slate-500">Read-only</span>
              ) : null}
            </div>
            <p className="mt-0.5 text-sm text-slate-600">
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

      <div
        className="mb-3 flex shrink-0 flex-wrap gap-2"
        role="tablist"
        aria-label="Disaster dashboard sections"
      >
        {DISASTER_DETAIL_TABS.map((tab) => {
          const active = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={active}
              onClick={() => setActiveTab(tab.id)}
              className={`rounded-md px-3 py-1.5 text-sm font-medium transition-colors ${
                active
                  ? "bg-[#002D62] text-white shadow-sm"
                  : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
              }`}
            >
              {tab.label}
            </button>
          );
        })}
      </div>

      {activeTab === "overview" ? (
        <DisasterOverviewTab dashboard={dashboard} />
      ) : null}

      {activeTab !== "overview" ? (
        <div
          className="flex min-h-0 flex-1 flex-col rounded-xl border border-slate-200/80 bg-white p-4 shadow-sm lg:min-h-0 lg:overflow-y-auto lg:overscroll-y-contain"
          role="tabpanel"
        >
        {activeTab === "affected-areas" ? (
          <DisasterAffectedAreasTab
            disasterPublicUuid={disasterPublicUuid}
            dashboard={dashboard}
            isReadOnly={isReadOnly}
            onRefresh={handleRefresh}
          />
        ) : null}
        {activeTab === "shelter-network" ? (
          <DisasterShelterNetworkTab
            disasterPublicUuid={disasterPublicUuid}
            dashboard={dashboard}
            facilities={facilities}
            facilityLocations={facilityLocations}
            isReadOnly={isReadOnly}
            onRefresh={handleRefresh}
          />
        ) : null}
        {activeTab === "relief-hubs" ? (
          <DisasterReliefHubsNetworkTab
            disasterPublicUuid={disasterPublicUuid}
            dashboard={dashboard}
            facilities={facilities}
            facilityLocations={facilityLocations}
            isReadOnly={isReadOnly}
            onRefresh={handleRefresh}
          />
        ) : null}
        {activeTab === "support-facilities" ? (
          <DisasterSupportFacilitiesTab
            dashboard={dashboard}
            facilities={facilities}
          />
        ) : null}
        {activeTab === "agencies" ? (
          <DisasterResponsibilitiesTab
            disasterPublicUuid={disasterPublicUuid}
            dashboard={dashboard}
            isReadOnly={isReadOnly}
            onRefresh={handleRefresh}
          />
        ) : null}
        {activeTab === "incidents" ? (
          <DisasterIncidentsTab
            disasterPublicUuid={disasterPublicUuid}
            dashboard={dashboard}
            isReadOnly={isReadOnly}
            onRefresh={handleRefresh}
          />
        ) : null}
        {activeTab === "relief" ? (
          <DisasterReliefTab
            disasterPublicUuid={disasterPublicUuid}
            dashboard={dashboard}
            isReadOnly={isReadOnly}
            onRefresh={handleRefresh}
          />
        ) : null}
        {activeTab === "timeline" ? (
          <DisasterTimelineTab
            disasterPublicUuid={disasterPublicUuid}
            dashboard={dashboard}
            isReadOnly={isReadOnly}
            onRefresh={handleRefresh}
          />
        ) : null}
        </div>
      ) : null}

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
