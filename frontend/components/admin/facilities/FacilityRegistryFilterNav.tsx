"use client";

import {
  FACILITY_REGISTRY_TABS,
  filterFacilitiesByRegistryTab,
  type FacilityRegistryTab,
} from "@/lib/admin-facility-readiness";
import type { AdminFacilityListItem } from "@/types/admin-facility";

type FacilityRegistryFilterNavProps = {
  activeTab: FacilityRegistryTab;
  onSelect: (tab: FacilityRegistryTab) => void;
  tabCounts: Record<FacilityRegistryTab, number>;
  layout?: "horizontal" | "vertical";
};

function getFilterButtonClass(active: boolean, layout: "horizontal" | "vertical") {
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

export function computeFacilityRegistryTabCounts(
  facilities: AdminFacilityListItem[],
): Record<FacilityRegistryTab, number> {
  return FACILITY_REGISTRY_TABS.reduce(
    (counts, tab) => {
      counts[tab.id] = filterFacilitiesByRegistryTab(facilities, tab.id).length;
      return counts;
    },
    {} as Record<FacilityRegistryTab, number>,
  );
}

export function FacilityRegistryFilterNav({
  activeTab,
  onSelect,
  tabCounts,
  layout = "vertical",
}: FacilityRegistryFilterNavProps) {
  const isVertical = layout === "vertical";

  return (
    <nav
      role="tablist"
      aria-label="Facility filters"
      aria-orientation={isVertical ? "vertical" : "horizontal"}
      className={
        isVertical
          ? "flex flex-col gap-1 p-2"
          : "flex gap-1.5 overflow-x-auto overscroll-x-contain [-ms-overflow-style:none] [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
      }
    >
      {FACILITY_REGISTRY_TABS.map((tab) => {
        const active = activeTab === tab.id;
        return (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onSelect(tab.id)}
            className={getFilterButtonClass(active, layout)}
          >
            <span>{tab.label}</span>
            <span
              className={`tabular-nums ${
                isVertical
                  ? active
                    ? "text-white/80"
                    : "text-slate-400"
                  : ""
              }`}
            >
              {tabCounts[tab.id]}
            </span>
          </button>
        );
      })}
    </nav>
  );
}
