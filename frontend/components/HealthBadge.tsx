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

  return (
    <span
      className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-semibold ${
        isRunning
          ? "bg-green-50 text-green-700"
          : status === "checking"
            ? "bg-gray-100 text-gray-700"
            : "bg-red-50 text-red-700"
      }`}
      title="API health status"
    >
      <span
        className={`h-2 w-2 rounded-full ${
          isRunning
            ? "bg-green-500"
            : status === "checking"
              ? "bg-gray-400"
              : "bg-red-500"
        }`}
      />
      API {status === "checking" ? "checking" : isRunning ? "online" : "offline"}
    </span>
  );
}
