"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";
import { AdminPageHeader } from "@/components/admin/AdminPageHeader";
import { DisasterListRow } from "@/components/admin/disasters/DisasterListRow";
import { Button } from "@/components/ui/Button";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { listDisasters } from "@/lib/disaster-operations-api";
import type { DisasterListItem } from "@/types/disaster-operations";

export function DisastersWorkspace() {
  const router = useRouter();
  const [disasters, setDisasters] = useState<DisasterListItem[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadDisasters = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await listDisasters();
      setDisasters(data.disasters);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load disasters.",
      );
      setDisasters([]);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadDisasters();
  }, [loadDisasters]);

  const resultLabel =
    disasters.length === 1
      ? "1 disaster"
      : `${disasters.length} disasters`;

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2 lg:overflow-hidden">
      <AdminPageHeader
        title="Natural Disasters"
        subtitle="Create, declare, and monitor disaster events."
        action={
          <div className="flex flex-wrap items-center gap-2">
            <p className="text-sm text-slate-600">{resultLabel}</p>
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={() => void loadDisasters()}
              disabled={isLoading}
              aria-label="Refresh disasters"
            >
              <RefreshCw
                className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`}
              />
            </Button>
            <Button
              type="button"
              variant="emergency"
              size="sm"
              onClick={() => router.push("/dashboard/admin/disasters/new")}
            >
              + Declare Disaster
            </Button>
          </div>
        }
      />

      {error ? <ErrorAlert message={error} /> : null}

      <div className="flex min-h-0 flex-1 flex-col rounded-xl border border-slate-200/80 bg-white shadow-sm lg:overflow-hidden">
        <div className="min-h-0 flex-1 overflow-y-auto overscroll-y-contain p-3 lg:p-4">
          {isLoading && disasters.length === 0 ? (
            <LoadingSkeleton lines={6} />
          ) : !isLoading && disasters.length === 0 ? (
            <p className="py-8 text-center text-sm text-slate-600">
              No disasters declared yet.
            </p>
          ) : (
            <ul className="space-y-2">
              {disasters.map((disaster) => (
                <DisasterListRow key={disaster.public_uuid} disaster={disaster} />
              ))}
            </ul>
          )}
        </div>
      </div>
    </div>
  );
}
