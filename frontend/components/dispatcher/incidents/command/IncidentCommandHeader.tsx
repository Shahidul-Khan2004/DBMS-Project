"use client";

import Link from "next/link";
import { Button } from "@/components/ui/Button";
export function IncidentCommandHeader({
  isTerminalIncident = false,
  onResolve,
  onClose,
  onCancel,
}: {
  isTerminalIncident?: boolean;
  onResolve: () => void;
  onClose: () => void;
  onCancel: () => void;
}) {
  return (
    <header className="shrink-0">
      <div className="flex flex-wrap items-center justify-between gap-x-2 gap-y-1.5">
        <nav
          aria-label="Incident command context"
          className="flex min-w-0 flex-wrap items-center gap-x-1 text-xs"
        >
          <Link
            href="/dashboard/dispatcher/incidents"
            className="font-medium text-[#006747] transition hover:text-[#002D62]"
          >
            ← Active Incidents
          </Link>
          <span className="text-slate-400" aria-hidden>
            /
          </span>
          <span className="text-slate-500">Incident Command</span>
        </nav>

        <div className="flex flex-wrap items-center justify-end gap-2">
          <Button
            type="button"
            variant="secondary"
            size="sm"
            disabled={isTerminalIncident}
            onClick={onResolve}
          >
            Resolve Incident
          </Button>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            disabled={isTerminalIncident}
            onClick={onClose}
          >
            Close Incident
          </Button>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            disabled={isTerminalIncident}
            onClick={onCancel}
          >
            Cancel Incident
          </Button>
        </div>
      </div>
    </header>
  );
}
