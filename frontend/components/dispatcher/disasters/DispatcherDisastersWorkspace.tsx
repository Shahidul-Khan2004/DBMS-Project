"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { AlertCircle } from "lucide-react";
import { DisasterSummaryRow } from "@/components/dispatcher/disasters/DisasterSummaryRow";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { EmptyState } from "@/components/ui/StatusState";
import { listOperationsDisasters } from "@/lib/disaster-operations-api";
import { sortOperationsDisastersForDispatcher } from "@/lib/disaster-operations-format";
import type { OperationsDisasterSummary } from "@/lib/disaster-operations-types";

export function DispatcherDisastersWorkspace() {
  const [disasters, setDisasters] = useState<OperationsDisasterSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadDisasters = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listOperationsDisasters();
      setDisasters(data);
    } catch {
      setError("Unable to load national disasters. Please try again.");
      setDisasters([]);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadDisasters();
  }, [loadDisasters]);

  const sortedDisasters = useMemo(
    () => sortOperationsDisastersForDispatcher(disasters),
    [disasters],
  );

  return (
    <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
      <header className="mb-3 flex shrink-0 flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold text-slate-900">National Disaster</h2>
          <p className="mt-0.5 text-sm text-slate-600">
            Disaster protocols created by System Admin appear here for dispatcher
            monitoring and incident linkage.
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

      {error ? (
        <div className="mb-3 shrink-0">
          <ErrorAlert message={error} />
        </div>
      ) : null}

      <section className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain rounded-2xl border border-slate-200/80 bg-white p-4 shadow-sm">
        {loading ? (
          <div className="space-y-2" aria-busy="true">
            <div className="h-20 animate-pulse rounded-xl bg-slate-100" />
            <div className="h-20 animate-pulse rounded-xl bg-slate-100" />
          </div>
        ) : !error && sortedDisasters.length === 0 ? (
          <div className="rounded-xl border border-[#991B1B]/20 bg-gradient-to-b from-red-50/80 to-white p-6 shadow-sm">
            <EmptyState
              title="No national disaster protocol is active."
              description="System Admin-created disaster protocols will appear here. Dispatchers can use this section to monitor disaster context and link emergency incidents when a national disaster is opened."
              icon={
                <AlertCircle className="h-6 w-6 text-[#B91C1C]" aria-hidden />
              }
              action={
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={loading}
                  onClick={() => void loadDisasters()}
                >
                  Refresh
                </Button>
              }
            />
          </div>
        ) : (
          <ul className="space-y-2">
            {sortedDisasters.map((disaster) => (
              <DisasterSummaryRow key={disaster.public_uuid} disaster={disaster} />
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
