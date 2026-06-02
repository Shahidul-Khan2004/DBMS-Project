"use client";

import { Info } from "lucide-react";
import { useState } from "react";
import { OversightIncidentsTab } from "@/components/admin/dispatcher-oversight/OversightIncidentsTab";
import { OversightIntakeTab } from "@/components/admin/dispatcher-oversight/OversightIntakeTab";
import { OversightOperationalReportsTab } from "@/components/admin/dispatcher-oversight/OversightOperationalReportsTab";
import { OversightServiceCasesTab } from "@/components/admin/dispatcher-oversight/OversightServiceCasesTab";

type OversightTab = "intake" | "incidents" | "cases" | "reports";

const TABS: { id: OversightTab; label: string }[] = [
  { id: "intake", label: "Intake Reports" },
  { id: "incidents", label: "Incidents" },
  { id: "cases", label: "Service Cases" },
  { id: "reports", label: "Operational Reports" },
];

const ATTRIBUTION_HINT =
  "Operator attribution is shown only where available from the current API. Verification and flagging can be added later when audit endpoints are introduced.";

export function DispatcherOversightWorkspace() {
  const [activeTab, setActiveTab] = useState<OversightTab>("intake");

  return (
    <div className="flex min-h-0 flex-1 flex-col lg:overflow-hidden">
      <header className="mb-4 flex shrink-0 items-center gap-2">
        <h2 className="text-xl font-semibold text-slate-900">
          Dispatcher Oversight
        </h2>
        <button
          type="button"
          className="rounded text-slate-400 transition-colors hover:text-slate-600 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#002D62]"
          title={ATTRIBUTION_HINT}
          aria-label={ATTRIBUTION_HINT}
        >
          <Info className="h-4 w-4" aria-hidden />
        </button>
      </header>

      <div
        className="mb-5 flex shrink-0 flex-wrap gap-2"
        role="tablist"
        aria-label="Dispatcher oversight sections"
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
        {activeTab === "intake" ? <OversightIntakeTab /> : null}
        {activeTab === "incidents" ? <OversightIncidentsTab /> : null}
        {activeTab === "cases" ? <OversightServiceCasesTab /> : null}
        {activeTab === "reports" ? <OversightOperationalReportsTab /> : null}
      </div>
    </div>
  );
}
