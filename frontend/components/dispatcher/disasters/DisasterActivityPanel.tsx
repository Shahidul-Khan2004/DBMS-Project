"use client";

import { DisasterOverviewSectionCard } from "@/components/dispatcher/disasters/DisasterOverviewSectionCard";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/StatusState";
import { formatBangladeshTime } from "@/lib/datetime";
import { formatDisasterStatusLabel } from "@/lib/disaster-operations-format";
import type { OperationsDisasterDashboard } from "@/lib/disaster-operations-types";

export function DisasterActivityPanel({
  dashboard,
  scrollBody = true,
  includeAudit = true,
  className = "",
}: {
  dashboard: OperationsDisasterDashboard;
  scrollBody?: boolean;
  includeAudit?: boolean;
  className?: string;
}) {
  const declarations = dashboard.declarations ?? [];
  const statusHistory = dashboard.status_history ?? [];
  const auditLogs = includeAudit ? (dashboard.recent_audit_logs ?? []) : [];
  const hasActivity =
    declarations.length > 0 || statusHistory.length > 0 || auditLogs.length > 0;

  return (
    <DisasterOverviewSectionCard
      title="Disaster Activity"
      subtitle={
        includeAudit
          ? "Declarations, status changes, and audit"
          : "Declarations and status changes"
      }
      className={scrollBody ? `min-h-0 h-full ${className}`.trim() : className}
      scrollBody={scrollBody}
    >
      {!hasActivity ? (
        <EmptyState
          title="No activity recorded"
          description="Disaster declarations and status history will appear here."
        />
      ) : (
        <div className="space-y-4">
          {declarations.length > 0 ? (
            <section>
              <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                Declarations
              </h4>
              <ul className="mt-2 space-y-1.5">
                {declarations.map((declaration) => (
                  <li
                    key={declaration.public_uuid}
                    className="rounded-lg border border-slate-100 bg-slate-50 px-3 py-2"
                  >
                    <p className="text-sm font-medium text-slate-900">
                      {declaration.title}
                    </p>
                    {declaration.issued_at ? (
                      <p className="mt-0.5 text-xs text-slate-600">
                        Issued {formatBangladeshTime(declaration.issued_at)}
                      </p>
                    ) : null}
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          {statusHistory.length > 0 ? (
            <section>
              <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                Status History
              </h4>
              <ul className="mt-2 space-y-1.5">
                {statusHistory.map((entry, index) => (
                  <li
                    key={`${entry.status_code}-${entry.recorded_at}-${index}`}
                    className="flex items-start justify-between gap-2 rounded-lg border border-slate-100 bg-slate-50 px-3 py-2"
                  >
                    <div className="min-w-0">
                      {entry.status_code ? (
                        <Badge size="compact" tone="neutral">
                          {formatBadgeLabel(
                            formatDisasterStatusLabel(entry.status_code),
                          )}
                        </Badge>
                      ) : null}
                      {entry.note ? (
                        <p className="mt-1 text-xs text-slate-600">{entry.note}</p>
                      ) : null}
                    </div>
                    {entry.recorded_at ? (
                      <span className="shrink-0 text-xs text-slate-500">
                        {formatBangladeshTime(entry.recorded_at)}
                      </span>
                    ) : null}
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          {includeAudit && auditLogs.length > 0 ? (
            <section>
              <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                Recent Audit
              </h4>
              <ul className="mt-2 space-y-1.5">
                {auditLogs.map((log) => (
                  <li
                    key={log.id ?? `${log.action}-${log.created_at}`}
                    className="rounded-lg border border-slate-100 bg-slate-50 px-3 py-2 text-xs text-slate-600"
                  >
                    <span className="font-medium text-slate-800">
                      {log.action ?? "Action"}
                    </span>
                    {log.entity_type ? ` · ${log.entity_type}` : ""}
                    {log.created_at ? (
                      <span className="mt-0.5 block text-slate-500">
                        {formatBangladeshTime(log.created_at)}
                      </span>
                    ) : null}
                  </li>
                ))}
              </ul>
            </section>
          ) : null}
        </div>
      )}
    </DisasterOverviewSectionCard>
  );
}

/** Mini activity card for Link Reports left column */
export function DisasterActivityMiniCard({
  dashboard,
}: {
  dashboard: OperationsDisasterDashboard;
}) {
  return (
    <DisasterActivityPanel
      dashboard={dashboard}
      scrollBody={false}
      includeAudit={false}
    />
  );
}
