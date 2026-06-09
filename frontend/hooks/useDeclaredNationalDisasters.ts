"use client";

import { useEffect, useState } from "react";
import { listPublicDisasters } from "@/lib/public-disasters-api";
import type { PublicDisaster } from "@/types/public-disaster";

const POLL_INTERVAL_MS = 60_000;

export function useDeclaredNationalDisasters() {
  const [disasters, setDisasters] = useState<PublicDisaster[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;

    async function loadDisasters() {
      try {
        const data = await listPublicDisasters();
        if (cancelled) return;

        setDisasters(
          data.disasters.filter(
            (disaster) => disaster.disaster_status === "declared",
          ),
        );
      } catch {
        if (!cancelled) setDisasters([]);
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    }

    void loadDisasters();
    const intervalId = window.setInterval(loadDisasters, POLL_INTERVAL_MS);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, []);

  return { disasters, isLoading };
}
