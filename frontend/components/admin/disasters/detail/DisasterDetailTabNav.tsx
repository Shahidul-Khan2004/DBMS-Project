"use client";

import {
  excludeFacilitiesByPublicUuid,
  getAffectedAdminAreaIds,
  isFacilityInAffectedArea,
} from "@/components/admin/disasters/detail/disasterFacilityPickerHelpers";
import { SUPPORT_FACILITY_TYPES } from "@/components/admin/disasters/detail/disasterResourceHelpers";
import {
  DISASTER_DETAIL_TABS,
  type DisasterDetailTab,
} from "@/components/admin/disasters/detail/disasterDetailTabs";
import {
  getActiveDisasterReliefHubFacilityUuids,
  getActiveDisasterShelterFacilityUuids,
} from "@/lib/disaster-operations-format";
import type { AdminFacilityListItem } from "@/types/admin-facility";
import type { DisasterDashboardResponse } from "@/types/disaster-operations";

type DisasterDetailTabNavProps = {
  activeTab: DisasterDetailTab;
  onSelect: (tab: DisasterDetailTab) => void;
  tabCounts: Partial<Record<DisasterDetailTab, number>>;
  layout?: "horizontal" | "vertical";
};

function getTabButtonClass(active: boolean, layout: "horizontal" | "vertical") {
  const base =
    "text-sm font-medium transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62]";
  const activeClass = "bg-[#002D62] text-white shadow-sm";
  const inactiveClass =
    "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50";

  if (layout === "vertical") {
    return `${base} flex w-full items-center justify-between gap-2 rounded-md px-3 py-2 text-left ${
      active ? activeClass : inactiveClass
    }`;
  }

  return `${base} shrink-0 whitespace-nowrap rounded-md px-2.5 py-1 ${
    active ? activeClass : inactiveClass
  }`;
}

export function computeDisasterDetailTabCounts(
  dashboard: DisasterDashboardResponse,
  facilities: AdminFacilityListItem[],
): Partial<Record<DisasterDetailTab, number>> {
  const affectedAdminAreaIds = getAffectedAdminAreaIds(dashboard);
  const activatedResourceFacilityUuids = getActiveDisasterShelterFacilityUuids(
    dashboard.shelters,
  );
  for (const uuid of getActiveDisasterReliefHubFacilityUuids(dashboard.relief_hubs)) {
    activatedResourceFacilityUuids.add(uuid);
  }

  const supportFacilityCount = excludeFacilitiesByPublicUuid(
    facilities.filter(
      (f) =>
        f.isActive &&
        SUPPORT_FACILITY_TYPES.has(f.facilityTypeCode) &&
        isFacilityInAffectedArea(f, affectedAdminAreaIds),
    ),
    activatedResourceFacilityUuids,
  ).length;

  const timelineCount =
    (dashboard.declarations?.length ?? 0) +
    (dashboard.status_history?.length ?? 0) +
    (dashboard.recent_audit_logs?.length ?? 0);

  return {
    "affected-areas": dashboard.affected_areas?.length ?? 0,
    "shelter-network": dashboard.shelters?.length ?? 0,
    "relief-hubs": dashboard.relief_hubs?.length ?? 0,
    "support-facilities": supportFacilityCount,
    agencies: dashboard.responsibilities?.length ?? 0,
    incidents: dashboard.linked_incidents?.length ?? 0,
    relief: dashboard.relief_requests?.length ?? 0,
    timeline: timelineCount,
  };
}

export function DisasterDetailTabNav({
  activeTab,
  onSelect,
  tabCounts,
  layout = "vertical",
}: DisasterDetailTabNavProps) {
  const isVertical = layout === "vertical";

  return (
    <nav
      role="tablist"
      aria-label="Disaster dashboard sections"
      aria-orientation={isVertical ? "vertical" : "horizontal"}
      className={
        isVertical
          ? "flex flex-col gap-1 p-2"
          : "flex gap-1.5 overflow-x-auto overscroll-x-contain [-ms-overflow-style:none] [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
      }
    >
      {DISASTER_DETAIL_TABS.map((tab) => {
        const active = activeTab === tab.id;
        const count = tabCounts[tab.id];
        return (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onSelect(tab.id)}
            className={getTabButtonClass(active, layout)}
          >
            <span>{tab.label}</span>
            {count != null ? (
              <span
                className={`tabular-nums ${
                  isVertical
                    ? active
                      ? "text-white/80"
                      : "text-slate-400"
                    : ""
                }`}
              >
                {count}
              </span>
            ) : null}
          </button>
        );
      })}
    </nav>
  );
}
