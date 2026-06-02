"use client";

import Link from "next/link";
import { useState } from "react";
import { RefreshCw } from "lucide-react";
import { DisasterAffectedAreasTab } from "@/components/admin/disasters/detail/DisasterAffectedAreasTab";
import { DisasterDeclarationsTab } from "@/components/admin/disasters/detail/DisasterDeclarationsTab";
import { DisasterIncidentsTab } from "@/components/admin/disasters/detail/DisasterIncidentsTab";
import { DisasterOverviewTab } from "@/components/admin/disasters/detail/DisasterOverviewTab";
import { DisasterReliefDistributionsTab } from "@/components/admin/disasters/detail/DisasterReliefDistributionsTab";
import { DisasterReliefHubsTab } from "@/components/admin/disasters/detail/DisasterReliefHubsTab";
import { DisasterReliefRequestsTab } from "@/components/admin/disasters/detail/DisasterReliefRequestsTab";
import { DisasterResponsibilitiesTab } from "@/components/admin/disasters/detail/DisasterResponsibilitiesTab";
import { DisasterSheltersTab } from "@/components/admin/disasters/detail/DisasterSheltersTab";
import { DisasterStatusActionDialog } from "@/components/admin/disasters/detail/DisasterStatusActionDialog";
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
import {
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
          href="/dashboard/admin/disasters"
          className="text-sm font-medium text-[#002D62] hover:underline"
        >
          ← Natural Disasters
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
      <div className="mb-4 shrink-0 space-y-3">
        <Link
          href="/dashboard/admin/disasters"
          className="text-sm font-medium text-[#002D62] hover:underline"
        >
          ← Natural Disasters
        </Link>

        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
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
            <p className="mt-0.5 text-sm text-slate-600">{disaster.event_code}</p>
          </div>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={() => void handleRefresh()}
            disabled={isRefreshing}
            aria-label="Refresh disaster dashboard"
          >
            <RefreshCw
              className={`h-4 w-4 ${isRefreshing ? "animate-spin" : ""}`}
              aria-hidden
            />
            Refresh
          </Button>
        </div>

        {!isReadOnly && (lifecycleActions.length > 0 || canAmend) ? (
          <div className="flex flex-wrap gap-2">
            {lifecycleActions.includes("resolve") ? (
              <Button
                type="button"
                size="sm"
                onClick={() => setLifecycleAction("resolve")}
              >
                Resolve disaster
              </Button>
            ) : null}
            {lifecycleActions.includes("close") ? (
              <Button
                type="button"
                size="sm"
                onClick={() => setLifecycleAction("close")}
              >
                Close disaster
              </Button>
            ) : null}
            {lifecycleActions.includes("cancel") ? (
              <Button
                type="button"
                variant="danger"
                size="sm"
                onClick={() => setLifecycleAction("cancel")}
              >
                Cancel disaster
              </Button>
            ) : null}
            {canAmend ? (
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => setAmendOpen(true)}
              >
                Amend declaration
              </Button>
            ) : null}
          </div>
        ) : null}
      </div>

      <div
        className="mb-4 flex shrink-0 flex-wrap gap-2"
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

      <div
        className="flex min-h-0 flex-1 flex-col rounded-xl border border-slate-200/80 bg-white p-4 shadow-sm lg:overflow-y-auto lg:overscroll-y-contain"
        role="tabpanel"
      >
        {activeTab === "overview" ? (
          <DisasterOverviewTab dashboard={dashboard} />
        ) : null}
        {activeTab === "affected-areas" ? (
          <DisasterAffectedAreasTab
            disasterPublicUuid={disasterPublicUuid}
            dashboard={dashboard}
            isReadOnly={isReadOnly}
            onRefresh={handleRefresh}
          />
        ) : null}
        {activeTab === "responsibilities" ? (
          <DisasterResponsibilitiesTab
            disasterPublicUuid={disasterPublicUuid}
            dashboard={dashboard}
            isReadOnly={isReadOnly}
            onRefresh={handleRefresh}
          />
        ) : null}
        {activeTab === "declarations" ? (
          <DisasterDeclarationsTab
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
        {activeTab === "shelters" ? (
          <DisasterSheltersTab
            disasterPublicUuid={disasterPublicUuid}
            dashboard={dashboard}
            facilities={facilities}
            facilityLocations={facilityLocations}
            isReadOnly={isReadOnly}
            onRefresh={handleRefresh}
          />
        ) : null}
        {activeTab === "relief-hubs" ? (
          <DisasterReliefHubsTab
            disasterPublicUuid={disasterPublicUuid}
            dashboard={dashboard}
            facilities={facilities}
            facilityLocations={facilityLocations}
            isReadOnly={isReadOnly}
            onRefresh={handleRefresh}
          />
        ) : null}
        {activeTab === "relief-requests" ? (
          <DisasterReliefRequestsTab
            disasterPublicUuid={disasterPublicUuid}
            dashboard={dashboard}
            isReadOnly={isReadOnly}
            onRefresh={handleRefresh}
          />
        ) : null}
        {activeTab === "relief-distributions" ? (
          <DisasterReliefDistributionsTab
            disasterPublicUuid={disasterPublicUuid}
            dashboard={dashboard}
            isReadOnly={isReadOnly}
            onRefresh={handleRefresh}
          />
        ) : null}
      </div>

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
