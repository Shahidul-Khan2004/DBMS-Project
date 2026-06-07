"use client";

import { useEffect, useState } from "react";
import { listOperationsDisasters } from "@/lib/disaster-operations-api";
import {
  countDispatcherActiveDisasters,
  filterDispatcherActiveDisasters,
} from "@/lib/disaster-operations-format";
import type { OperationsDisasterSummary } from "@/lib/disaster-operations-types";

export function useDispatcherActiveDisasters() {
  const [disasters, setDisasters] = useState<OperationsDisasterSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [fetchFailed, setFetchFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;

    void listOperationsDisasters()
      .then((data) => {
        if (!cancelled) {
          setDisasters(data);
          setFetchFailed(false);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setDisasters([]);
          setFetchFailed(true);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const activeDisasters = filterDispatcherActiveDisasters(disasters);
  const activeCount = countDispatcherActiveDisasters(disasters);
  const totalCount = disasters.length;

  return {
    disasters,
    activeDisasters,
    activeCount,
    totalCount,
    hasActive: activeCount > 0,
    fetchFailed,
    loading,
  };
}
