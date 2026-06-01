"use client";

import { RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/Button";

type AgenciesToolbarProps = {
  resultLabel: string;
  total: number;
  limit: number;
  offset: number;
  isLoading: boolean;
  className?: string;
  onRefresh: () => void;
  onPrev: () => void;
  onNext: () => void;
  onOnboard: () => void;
};

export function AgenciesToolbar({
  resultLabel,
  total,
  limit,
  offset,
  isLoading,
  className = "",
  onRefresh,
  onPrev,
  onNext,
  onOnboard,
}: AgenciesToolbarProps) {
  const canPrev = offset > 0;
  const canNext = offset + limit < total;

  return (
    <div
      className={`flex flex-wrap items-center justify-end gap-2 ${className}`.trim()}
    >
      <p className="text-sm text-slate-600">{resultLabel}</p>
      <Button
        type="button"
        variant="secondary"
        size="sm"
        onClick={onPrev}
        disabled={!canPrev || isLoading}
      >
        Previous
      </Button>
      <Button
        type="button"
        variant="secondary"
        size="sm"
        onClick={onNext}
        disabled={!canNext || isLoading}
      >
        Next
      </Button>
      <Button
        type="button"
        variant="secondary"
        size="sm"
        onClick={onRefresh}
        disabled={isLoading}
        aria-label="Refresh agencies"
      >
        <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
      </Button>
      <Button type="button" size="sm" onClick={onOnboard}>
        Onboard agency
      </Button>
    </div>
  );
}
