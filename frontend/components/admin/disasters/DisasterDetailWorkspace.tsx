"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { ErrorAlert } from "@/components/ui/ErrorAlert";
import { LoadingSkeleton } from "@/components/ui/LoadingSkeleton";
import { getDisasterDashboard } from "@/lib/disaster-operations-api";
import {
  formatAffectedAreaLabel,
  formatDisasterEventTypeLabel,
  formatDisasterSeverityLabel,
  formatDisasterStatusLabel,
  getDeclarationStatusSummary,
} from "@/lib/disaster-operations-format";
import type { DisasterDashboardResponse } from "@/types/disaster-operations";
import { formatBangladeshTime } from "@/lib/datetime";

type DisasterDetailWorkspaceProps = {
  disasterPublicUuid: string;
};

export function DisasterDetailWorkspace({
  disasterPublicUuid,
}: DisasterDetailWorkspaceProps) {
  const [dashboard, setDashboard] = useState<DisasterDashboardResponse | null>(
    null,
  );
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadDashboard = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await getDisasterDashboard(disasterPublicUuid);
      setDashboard(data);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Failed to load disaster dashboard.",
      );
      setDashboard(null);
    } finally {
      setIsLoading(false);
    }
  }, [disasterPublicUuid]);

  useEffect(() => {
    void loadDashboard();
  }, [loadDashboard]);

  if (isLoading && !dashboard) {
    return <LoadingSkeleton lines={10} />;
  }

  if (error && !dashboard) {
    return (
      <div className="space-y-4">
        <Link
          href="/dashboard/admin/disasters"
          className="text-sm font-medium text-[#002D62] hover:underline"
        >
          ← Natural Disasters
        </Link>
        <ErrorAlert message={error} />
      </div>
    );
  }

  if (!dashboard) return null;

  const { disaster } = dashboard;
  const affectedAreas = dashboard.affected_areas ?? [];
  const declarations = dashboard.declarations ?? [];
  const responsibilities = dashboard.responsibilities ?? [];
  const linkedIncidents = dashboard.linked_incidents ?? [];
  const shelters = dashboard.shelters ?? [];
  const reliefHubs = dashboard.relief_hubs ?? [];

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-4 lg:overflow-y-auto">
      <div className="shrink-0">
        <Link
          href="/dashboard/admin/disasters"
          className="text-sm font-medium text-[#002D62] hover:underline"
        >
          ← Natural Disasters
        </Link>
        <h2 className="mt-2 text-xl font-semibold text-slate-900">
          {disaster.title}
        </h2>
        <p className="mt-0.5 text-sm text-slate-600">{disaster.event_code}</p>
      </div>

      <CommandSectionCard title="Summary">
        <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-3">
          <div>
            <dt className="text-xs font-medium text-slate-500">Status</dt>
            <dd className="mt-0.5">
              <Badge size="compact" tone="active">
                {formatBadgeLabel(formatDisasterStatusLabel(disaster.status_code))}
              </Badge>
            </dd>
          </div>
          <div>
            <dt className="text-xs font-medium text-slate-500">Severity</dt>
            <dd className="mt-0.5 text-slate-900">
              {formatDisasterSeverityLabel(disaster.severity_level)}
            </dd>
          </div>
          <div>
            <dt className="text-xs font-medium text-slate-500">Event type</dt>
            <dd className="mt-0.5 text-slate-900">
              {formatDisasterEventTypeLabel(
                disaster.event_type_code,
                disaster.event_type_name,
              )}
            </dd>
          </div>
          <div>
            <dt className="text-xs font-medium text-slate-500">
              Affected areas
            </dt>
            <dd className="mt-0.5 text-slate-900">{affectedAreas.length}</dd>
          </div>
          <div className="sm:col-span-2">
            <dt className="text-xs font-medium text-slate-500">Declarations</dt>
            <dd className="mt-0.5 text-slate-900">
              {getDeclarationStatusSummary(
                disaster.status_code,
                declarations.length,
              )}
            </dd>
          </div>
        </dl>
      </CommandSectionCard>

      <CommandSectionCard
        title="Affected Areas"
        subtitle={`${affectedAreas.length} upazila record(s)`}
        scrollableBody={affectedAreas.length > 6}
        fillHeight={false}
      >
        {affectedAreas.length === 0 ? (
          <p className="text-sm text-slate-600">No affected areas recorded.</p>
        ) : (
          <ul className="space-y-2">
            {affectedAreas.map((area) => (
              <li
                key={area.affected_area_public_uuid}
                className="rounded-lg border border-slate-100 px-3 py-2 text-sm"
              >
                <p className="font-medium text-slate-900">
                  {formatAffectedAreaLabel(area)}
                </p>
                {area.impact_level ? (
                  <p className="mt-0.5 text-xs text-slate-600">
                    Impact: {formatBadgeLabel(area.impact_level)}
                  </p>
                ) : null}
                {area.estimated_affected_people != null ? (
                  <p className="mt-0.5 text-xs text-slate-600">
                    Est. affected: {area.estimated_affected_people.toLocaleString()}
                  </p>
                ) : null}
                {area.assessment_note ? (
                  <p className="mt-1 text-xs text-slate-500">{area.assessment_note}</p>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </CommandSectionCard>

      <CommandSectionCard title="Declarations">
        {declarations.length === 0 ? (
          <p className="text-sm text-slate-600">No declarations on record.</p>
        ) : (
          <ul className="space-y-3">
            {declarations.map((decl) => (
              <li
                key={decl.public_uuid}
                className="rounded-lg border border-slate-100 px-3 py-2 text-sm"
              >
                <p className="font-medium text-slate-900">{decl.title}</p>
                {decl.issued_at ? (
                  <p className="mt-0.5 text-xs text-slate-500">
                    Issued {formatBangladeshTime(decl.issued_at)}
                  </p>
                ) : null}
                {decl.public_guidance ? (
                  <p className="mt-2 text-xs text-slate-700">
                    {decl.public_guidance}
                  </p>
                ) : null}
                {decl.reason ? (
                  <p className="mt-1 text-xs text-slate-500">
                    Reason: {decl.reason}
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </CommandSectionCard>

      {responsibilities.length > 0 ? (
        <CommandSectionCard title="Responsibilities">
          <ul className="space-y-2 text-sm">
            {responsibilities.map((r) => (
              <li
                key={`${r.agency_public_uuid}-${r.responsibility_type}`}
                className="rounded-lg border border-slate-100 px-3 py-2"
              >
                <span className="font-medium text-slate-900">
                  {r.agency_name ?? "Agency"}
                </span>
                <span className="text-slate-600">
                  {" "}
                  · {formatBadgeLabel(r.responsibility_type)}
                  {r.is_lead ? " (lead)" : ""}
                </span>
              </li>
            ))}
          </ul>
        </CommandSectionCard>
      ) : null}

      {linkedIncidents.length > 0 ? (
        <CommandSectionCard title="Linked Incidents">
          <ul className="space-y-2 text-sm">
            {linkedIncidents.map((inc) => (
              <li
                key={inc.incident_public_uuid}
                className="rounded-lg border border-slate-100 px-3 py-2"
              >
                <p className="font-medium text-slate-900">
                  {inc.title ?? "Incident"}
                </p>
                <p className="text-xs text-slate-600">
                  {inc.incident_code}
                  {inc.incident_status
                    ? ` · ${formatBadgeLabel(inc.incident_status)}`
                    : ""}
                </p>
              </li>
            ))}
          </ul>
        </CommandSectionCard>
      ) : null}

      {shelters.length > 0 ? (
        <CommandSectionCard title="Shelters" subtitle="Read-only preview">
          <ul className="space-y-2 text-sm">
            {shelters.map((s) => (
              <li
                key={s.public_uuid ?? s.facility_public_uuid}
                className="rounded-lg border border-slate-100 px-3 py-2"
              >
                <p className="font-medium text-slate-900">
                  {s.facility_name ?? "Shelter facility"}
                </p>
                {s.activation_status ? (
                  <p className="text-xs text-slate-600">
                    {formatBadgeLabel(s.activation_status)}
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        </CommandSectionCard>
      ) : null}

      {reliefHubs.length > 0 ? (
        <CommandSectionCard title="Relief Hubs" subtitle="Read-only preview">
          <ul className="space-y-2 text-sm">
            {reliefHubs.map((h) => (
              <li
                key={h.public_uuid ?? h.facility_public_uuid}
                className="rounded-lg border border-slate-100 px-3 py-2"
              >
                <p className="font-medium text-slate-900">
                  {h.facility_name ?? "Relief hub"}
                </p>
                {h.activation_status ? (
                  <p className="text-xs text-slate-600">
                    {formatBadgeLabel(h.activation_status)}
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        </CommandSectionCard>
      ) : null}
    </div>
  );
}
