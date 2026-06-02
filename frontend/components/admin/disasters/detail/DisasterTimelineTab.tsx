"use client";

import { useState } from "react";
import { CommandSectionCard } from "@/components/dispatcher/incidents/command/CommandSectionCard";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { DeclarationAmendmentModal } from "@/components/admin/disasters/detail/DeclarationAmendmentModal";
import {
  formatDisasterStatusLabel,
  hasInitialDeclaration,
} from "@/lib/disaster-operations-format";
import type { DisasterDashboardResponse } from "@/types/disaster-operations";
import { formatBangladeshTime } from "@/lib/datetime";

type DisasterTimelineTabProps = {
  disasterPublicUuid: string;
  dashboard: DisasterDashboardResponse;
  isReadOnly: boolean;
  onRefresh: () => Promise<void>;
};

export function DisasterTimelineTab({
  disasterPublicUuid,
  dashboard,
  isReadOnly,
  onRefresh,
}: DisasterTimelineTabProps) {
  const [amendOpen, setAmendOpen] = useState(false);
  const declarations = dashboard.declarations ?? [];
  const statusHistory = dashboard.status_history ?? [];
  const auditLogs = dashboard.recent_audit_logs ?? [];
  const canAmend = !isReadOnly && hasInitialDeclaration(declarations);

  return (
    <div className="space-y-6">
      <CommandSectionCard
        title="Declarations"
        headerAction={
          canAmend ? (
            <Button type="button" size="sm" onClick={() => setAmendOpen(true)}>
              Issue Amendment
            </Button>
          ) : undefined
        }
      >
        {declarations.length === 0 ? (
          <p className="text-sm text-slate-600">No declarations on record.</p>
        ) : (
          <ul className="space-y-3">
            {declarations.map((decl) => (
              <li
                key={decl.public_uuid}
                className="rounded-lg border border-slate-100 px-3 py-2 text-sm"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <p className="font-medium text-slate-900">{decl.title}</p>
                  {decl.declaration_kind ? (
                    <Badge size="compact">
                      {formatBadgeLabel(decl.declaration_kind)}
                    </Badge>
                  ) : null}
                </div>
                {decl.issued_at ? (
                  <p className="mt-0.5 text-xs text-slate-500">
                    Issued {formatBangladeshTime(decl.issued_at)}
                  </p>
                ) : null}
                {decl.public_guidance ? (
                  <p className="mt-2 text-xs text-slate-700">{decl.public_guidance}</p>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </CommandSectionCard>

      <CommandSectionCard title="Status history">
        {statusHistory.length === 0 ? (
          <p className="text-sm text-slate-600">No status changes recorded.</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {statusHistory.map((entry, index) => (
              <li
                key={`${entry.recorded_at}-${index}`}
                className="rounded-lg border border-slate-100 px-3 py-2"
              >
                <p className="font-medium text-slate-900">
                  {entry.status_code
                    ? formatBadgeLabel(
                        formatDisasterStatusLabel(entry.status_code),
                      )
                    : "Status update"}
                </p>
                {entry.recorded_at ? (
                  <p className="text-xs text-slate-500">
                    {formatBangladeshTime(entry.recorded_at)}
                  </p>
                ) : null}
                {entry.note ? (
                  <p className="mt-1 text-xs text-slate-600">{entry.note}</p>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </CommandSectionCard>

      <CommandSectionCard title="Audit log">
        {auditLogs.length === 0 ? (
          <p className="text-sm text-slate-600">No recent audit entries.</p>
        ) : (
          <ul className="space-y-2 text-sm">
            {auditLogs.map((log) => (
              <li
                key={log.id ?? `${log.created_at}-${log.action}`}
                className="rounded-lg border border-slate-100 px-3 py-2"
              >
                <p className="font-medium text-slate-900">
                  {log.action ?? "Action"}
                  {log.entity_type ? (
                    <span className="font-normal text-slate-600">
                      {" "}
                      · {log.entity_type}
                    </span>
                  ) : null}
                </p>
                {log.created_at ? (
                  <p className="text-xs text-slate-500">
                    {formatBangladeshTime(log.created_at)}
                  </p>
                ) : null}
              </li>
            ))}
          </ul>
        )}
      </CommandSectionCard>

      <DeclarationAmendmentModal
        open={amendOpen}
        disasterPublicUuid={disasterPublicUuid}
        onClose={() => setAmendOpen(false)}
        onSuccess={onRefresh}
      />
    </div>
  );
}
