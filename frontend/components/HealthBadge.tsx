"use client";

import { useEffect, useState } from "react";
import { publicGet } from "@/lib/api";

type HealthResponse = {
  status?: string;
};

export function HealthBadge() {
  const [status, setStatus] = useState<"checking" | "running" | "down">(
    "checking",
  );

  useEffect(() => {
    let cancelled = false;

    async function checkHealth() {
      try {
        const data = await publicGet<HealthResponse>("/health");
        if (!cancelled) {
          setStatus(data.status === "RUNNING" ? "running" : "down");
        }
      } catch {
        if (!cancelled) setStatus("down");
      }
    }

    void checkHealth();
    const intervalId = window.setInterval(checkHealth, 30000);

    return () => {
      cancelled = true;
      window.clearInterval(intervalId);
    };
  }, []);

  const isRunning = status === "running";
  const statusLabel =
    status === "checking"
      ? "Server status checking"
      : isRunning
        ? "Server reachable"
        : "Server unreachable";

  return (
    <span
      className="inline-flex h-10 w-10 items-center justify-center"
      aria-label={statusLabel}
    >
      <span
        className={`h-3 w-3 rounded-full ${
          isRunning
            ? "bg-green-500"
            : status === "checking"
              ? "bg-gray-400"
              : "bg-red-500"
        }`}
      />
    </span>
  );
}
