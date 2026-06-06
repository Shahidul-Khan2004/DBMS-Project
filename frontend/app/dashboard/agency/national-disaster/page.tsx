"use client";

import { useCallback, useEffect, useState } from "react";
import { AgencyDashboardPage } from "@/components/agency/AgencyDashboardPage";
import { AgencyDisasterListRow } from "@/components/agency/national-disaster/AgencyDisasterListRow";
import { AgencyNationalDisasterBanner } from "@/components/agency/national-disaster/AgencyNationalDisasterBanner";
import { AgencySkeletonBlock } from "@/components/agency/AgencySkeletonBlock";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { EmptyState } from "@/components/ui/StatusState";
import { listAgencyDisasters } from "@/lib/agency-disaster-api";
import type { DisasterListItem } from "@/types/disaster-operations";

export default function AgencyNationalDisasterPage() {
  const [disasters, setDisasters] = useState<DisasterListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadDisasters = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listAgencyDisasters({ limit: 100, offset: 0 });
      setDisasters(data.disasters ?? []);
    } catch {
      setError("Unable to load national disaster assignments. Please try again.");
      setDisasters([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadDisasters();
  }, [loadDisasters]);

  return (
    <AgencyDashboardPage>
      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <header className="mb-3 flex shrink-0 flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-xl font-semibold text-slate-900">National Disaster</h2>
            <p className="mt-0.5 text-sm text-slate-600">
              Monitor assigned disasters, record shelter occupancy, and submit relief requests.
            </p>
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={loading}
            onClick={() => void loadDisasters()}
          >
            Refresh
          </Button>
        </header>

        <AgencyNationalDisasterBanner />

        {error ? (
          <div className="mb-3 shrink-0">
            <ErrorAlert message={error} />
          </div>
        ) : null}

        <section className="min-h-0 flex-1 overflow-y-auto rounded-2xl border border-slate-200/80 bg-white p-4 shadow-sm">
          <h3 className="mb-3 text-sm font-semibold text-slate-900">Assigned Disasters</h3>
          {loading ? (
            <div className="space-y-2" aria-busy="true">
              <AgencySkeletonBlock className="h-20 w-full" />
              <AgencySkeletonBlock className="h-20 w-full" />
            </div>
          ) : disasters.length === 0 ? (
            <EmptyState
              title="No national disaster assignments"
              description="Your agency has no active disaster responsibilities, managed shelters, or relief requests yet."
            />
          ) : (
            <ul className="space-y-2">
              {disasters.map((disaster) => (
                <AgencyDisasterListRow key={disaster.public_uuid} disaster={disaster} />
              ))}
            </ul>
          )}
        </section>
      </div>
    </AgencyDashboardPage>
  );
}
