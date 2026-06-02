"use client";

import { useState } from "react";
import { AdminPageHeader } from "@/components/admin/AdminPageHeader";
import { AgencyWorkloadReport } from "@/components/admin/reports/AgencyWorkloadReport";
import { ResponseTimingReport } from "@/components/admin/reports/ResponseTimingReport";

type ReportTab = "workload" | "timing";

const TABS: { id: ReportTab; label: string }[] = [
  { id: "workload", label: "Agency Workload" },
  { id: "timing", label: "Response Timing" },
];

export function AdminReportsWorkspace() {
  const [activeTab, setActiveTab] = useState<ReportTab>("workload");

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4 lg:overflow-hidden">
      <AdminPageHeader
        title="Reports"
        subtitle="Review backend-supported operational and agency insights."
      />

      <div
        className="flex shrink-0 flex-wrap gap-2"
        role="tablist"
        aria-label="Report type"
      >
        {TABS.map((tab) => {
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
        {activeTab === "workload" ? (
          <AgencyWorkloadReport />
        ) : (
          <ResponseTimingReport />
        )}
      </div>
    </div>
  );
}
