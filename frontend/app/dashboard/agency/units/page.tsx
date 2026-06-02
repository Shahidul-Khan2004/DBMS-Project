"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { AgencyDashboardPage } from "@/components/agency/AgencyDashboardPage";
import { AgencyFilterChips } from "@/components/agency/AgencyFilterChips";
import { AgencyUnitsPanel } from "@/components/agency/AgencyUnitsPanel";
import { Button } from "@/components/ui/Button";
import { getAgencyUnits } from "@/lib/agency-api";
import type { AgencyUnit } from "@/types/agency";

type UnitFilter = "all" | "available" | "busy" | "inactive";

const FILTER_OPTIONS: Array<{ value: UnitFilter; label: string }> = [
  { value: "all", label: "All" },
  { value: "available", label: "Available" },
  { value: "busy", label: "Busy" },
  { value: "inactive", label: "Inactive" },
];

function filterUnits(units: AgencyUnit[], filter: UnitFilter): AgencyUnit[] {
  switch (filter) {
    case "available":
      return units.filter((u) => u.is_active && u.status_code === "available");
    case "busy":
      return units.filter((u) => u.is_active && u.status_code === "busy");
    case "inactive":
      return units.filter((u) => !u.is_active);
    default:
      return units;
  }
}

export default function AgencyUnitsPage() {
  const [units, setUnits] = useState<AgencyUnit[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<UnitFilter>("all");

  const loadUnits = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getAgencyUnits({ limit: 100, offset: 0 });
      setUnits(data.units ?? []);
    } catch {
      setError("Unable to load units. Please try again.");
      setUnits([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadUnits();
  }, [loadUnits]);

  const filtered = useMemo(() => filterUnits(units, filter), [units, filter]);

  return (
    <AgencyDashboardPage>
      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <header className="mb-4 flex shrink-0 flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-xl font-semibold text-slate-900">Units</h2>
            <p className="mt-0.5 text-sm text-slate-600">
              Manage agency units, availability, and base locations.
            </p>
          </div>
          <Button type="button" variant="outline" size="sm" onClick={() => void loadUnits()}>
            Refresh
          </Button>
        </header>

        <div className="mb-4 shrink-0">
          <AgencyFilterChips
            options={FILTER_OPTIONS}
            value={filter}
            onChange={setFilter}
          />
        </div>

        <section className="min-h-0 flex-1 overflow-y-auto rounded-2xl border border-slate-200/80 bg-white p-4 shadow-sm">
          <AgencyUnitsPanel
            units={filtered}
            loading={loading}
            error={error}
            onRefresh={loadUnits}
          />
        </section>
      </div>
    </AgencyDashboardPage>
  );
}
