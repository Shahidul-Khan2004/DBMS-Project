"use client";

import { useCallback, useEffect, useState } from "react";
import { getOperationsDisaster } from "@/lib/disaster-operations-api";
import type { OperationsDisasterDashboard } from "@/lib/disaster-operations-types";

export function useDisasterCommandDashboard(disasterPublicUuid: string) {
  const [dashboard, setDashboard] = useState<OperationsDisasterDashboard | null>(
    null,
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!disasterPublicUuid) return;
    setLoading(true);
    setError(null);
    try {
      const data = await getOperationsDisaster(disasterPublicUuid);
      setDashboard(data);
    } catch {
      setError("Unable to load disaster details. Please try again.");
      setDashboard(null);
    } finally {
      setLoading(false);
    }
  }, [disasterPublicUuid]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return { dashboard, loading, error, refresh };
}
