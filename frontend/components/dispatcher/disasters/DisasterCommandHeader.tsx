"use client";

import Link from "next/link";
import type { ReactNode } from "react";
import { ArrowLeft } from "lucide-react";
import { DisasterCommandModeToggle } from "@/components/dispatcher/disasters/DisasterCommandModeToggle";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { dispatcherNationalDisasterLandingPath } from "@/lib/dispatcher-national-disaster-routes";
import {
  formatDisasterEventTypeLabel,
  formatDisasterSeverityLabel,
  formatDisasterStatusLabel,
} from "@/lib/disaster-operations-format";
import type { OperationsDisasterDashboard } from "@/lib/disaster-operations-types";
import type { DisasterCommandMode } from "@/lib/dispatcher-national-disaster-routes";

export function DisasterCommandHeader({
  mode,
  disasterPublicUuid,
  dashboard,
  actions,
}: {
  mode: DisasterCommandMode;
  disasterPublicUuid: string;
  dashboard: OperationsDisasterDashboard;
  actions?: ReactNode;
}) {
  const { disaster } = dashboard;

  return (
    <header className="shrink-0">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-end lg:justify-between">
        <div className="min-w-0">
          <Link
            href={dispatcherNationalDisasterLandingPath()}
            className="inline-flex items-center gap-1 text-sm font-medium text-[#002D62] hover:text-[#006747]"
          >
            <ArrowLeft className="h-4 w-4" aria-hidden />
            National Disaster
          </Link>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <h1 className="text-xl font-semibold text-slate-900">
              Disaster Command
            </h1>
            <Badge size="compact" tone="active">
              {formatBadgeLabel(formatDisasterStatusLabel(disaster.status_code))}
            </Badge>
            <Badge size="compact" tone="neutral">
              {formatDisasterSeverityLabel(disaster.severity_level)}
            </Badge>
            <Badge size="compact" tone="neutral">
              {formatDisasterEventTypeLabel(
                disaster.event_type_code,
                disaster.event_type_name,
              )}
            </Badge>
          </div>
          <p className="mt-0.5 truncate text-sm text-slate-600">
            {disaster.event_code} · {disaster.title}
          </p>
        </div>

        <div className="flex shrink-0 flex-wrap items-center gap-3">
          <DisasterCommandModeToggle
            mode={mode}
            disasterPublicUuid={disasterPublicUuid}
          />
          {actions ? (
            <div className="flex flex-wrap items-center gap-2">{actions}</div>
          ) : null}
        </div>
      </div>
    </header>
  );
}
