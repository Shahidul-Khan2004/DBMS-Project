"use client";

import { useState } from "react";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { ServiceCaseAssignmentTab } from "@/components/dispatcher/service-cases/detail/ServiceCaseAssignmentTab";
import { ServiceCaseOverviewTab } from "@/components/dispatcher/service-cases/detail/ServiceCaseOverviewTab";
import { ServiceCaseStatusHistoryTab } from "@/components/dispatcher/service-cases/detail/ServiceCaseStatusHistoryTab";
import type {
  OperationsServiceCase,
  ServiceCaseAssignment,
  ServiceCaseResolution,
  ServiceCaseStatusHistoryItem,
} from "@/types/service-case";

type ActivityTab = "overview" | "status_history" | "assignment";

function tabButtonClass(isActive: boolean) {
  return `inline-flex items-center rounded-lg px-2.5 py-1.5 text-xs font-semibold transition-colors ${
    isActive
      ? "bg-[#E8F2FF] text-[#002D62]"
      : "text-slate-600 hover:bg-slate-100 hover:text-slate-900"
  }`;
}

type ServiceCaseActivityContextPanelProps = {
  className?: string;
  serviceCase: OperationsServiceCase;
  statusHistory: ServiceCaseStatusHistoryItem[];
  assignments: ServiceCaseAssignment[];
  resolution: ServiceCaseResolution | null | undefined;
  linkedIncidentPublicUuid: string | null;
};

export function ServiceCaseActivityContextPanel({
  className = "",
  serviceCase,
  statusHistory,
  assignments,
  resolution,
  linkedIncidentPublicUuid,
}: ServiceCaseActivityContextPanelProps) {
  const [activeTab, setActiveTab] = useState<ActivityTab>("overview");

  return (
    <CommandSectionCard
      title="Case Activity & Context"
      fillHeight
      className={`min-h-0 flex-1 xl:h-full xl:overflow-hidden !p-3 sm:!p-4 ${className}`.trim()}
      bodyClassName="mt-2 flex min-h-0 flex-1 flex-col overflow-hidden"
    >
      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <div
          className="mb-1.5 flex shrink-0 flex-wrap gap-1 border-b border-slate-100 pb-2"
          role="tablist"
          aria-label="Case activity sections"
        >
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "overview"}
            className={tabButtonClass(activeTab === "overview")}
            onClick={() => setActiveTab("overview")}
          >
            Overview
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "status_history"}
            className={tabButtonClass(activeTab === "status_history")}
            onClick={() => setActiveTab("status_history")}
          >
            Status History
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === "assignment"}
            className={tabButtonClass(activeTab === "assignment")}
            onClick={() => setActiveTab("assignment")}
          >
            Assignment
          </button>
        </div>

        <div
          className="min-h-0 flex-1 xl:overflow-y-auto xl:overscroll-y-contain"
          role="tabpanel"
        >
          {activeTab === "overview" ? (
            <ServiceCaseOverviewTab
              serviceCase={serviceCase}
              resolution={resolution}
              linkedIncidentPublicUuid={linkedIncidentPublicUuid}
            />
          ) : null}
          {activeTab === "status_history" ? (
            <ServiceCaseStatusHistoryTab statusHistory={statusHistory} />
          ) : null}
          {activeTab === "assignment" ? (
            <ServiceCaseAssignmentTab assignments={assignments} />
          ) : null}
        </div>
      </div>
    </CommandSectionCard>
  );
}
