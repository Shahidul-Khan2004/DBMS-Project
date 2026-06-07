"use client";

import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { formatBangladeshTime } from "@/lib/datetime";
import { formatDisasterStatusLabel } from "@/lib/disaster-operations-format";
import type { OperationsDisasterDashboard } from "@/lib/disaster-operations-types";
import type {
  DisasterAuditLog,
  DisasterDeclaration,
  DisasterStatusHistoryEntry,
} from "@/types/disaster-operations";

export type DisasterActivityPreviewItem =
  | { kind: "declaration"; data: DisasterDeclaration }
  | { kind: "status"; data: DisasterStatusHistoryEntry; index: number }
  | { kind: "audit"; data: DisasterAuditLog };

const PREVIEW_LIMIT = 2;

function sortStatusHistoryNewestFirst(
  entries: DisasterStatusHistoryEntry[],
): DisasterStatusHistoryEntry[] {
  return [...entries].sort((left, right) => {
    const leftTime = left.recorded_at ? Date.parse(left.recorded_at) : 0;
    const rightTime = right.recorded_at ? Date.parse(right.recorded_at) : 0;
    return rightTime - leftTime;
  });
}

function getActivityItemTimestamp(item: DisasterActivityPreviewItem): number {
  if (item.kind === "declaration") {
    return item.data.issued_at ? Date.parse(item.data.issued_at) : 0;
  }
  if (item.kind === "status") {
    return item.data.recorded_at ? Date.parse(item.data.recorded_at) : 0;
  }
  return item.data.created_at ? Date.parse(item.data.created_at) : 0;
}

export function getActivityPreviewTitleSubtitle(item: DisasterActivityPreviewItem): {
  title: string;
  subtitle: string;
} {
  if (item.kind === "declaration") {
    return {
      title: item.data.title,
      subtitle: item.data.issued_at
        ? `Issued ${formatBangladeshTime(item.data.issued_at)}`
        : "Declaration",
    };
  }

  if (item.kind === "status") {
    const statusLabel = item.data.status_code
      ? formatBadgeLabel(formatDisasterStatusLabel(item.data.status_code))
      : "Status change";
    return {
      title: statusLabel,
      subtitle: item.data.note?.trim()
        ? item.data.note
        : item.data.recorded_at
          ? formatBangladeshTime(item.data.recorded_at)
          : "Status update",
    };
  }

  const action = item.data.action ?? "Action";
  const subtitleParts: string[] = [];
  if (item.data.entity_type) subtitleParts.push(item.data.entity_type);
  if (item.data.created_at) {
    subtitleParts.push(formatBangladeshTime(item.data.created_at));
  }
  return {
    title: action,
    subtitle: subtitleParts.join(" · ") || "Audit log",
  };
}

export function getDisasterActivityPreviewItems(
  dashboard: OperationsDisasterDashboard,
  includeAudit: boolean,
  limit = PREVIEW_LIMIT,
): DisasterActivityPreviewItem[] {
  const items: DisasterActivityPreviewItem[] = [];
  const declarations = dashboard.declarations ?? [];
  const statusHistory = sortStatusHistoryNewestFirst(
    dashboard.status_history ?? [],
  );
  const auditLogs = includeAudit ? (dashboard.recent_audit_logs ?? []) : [];

  for (const declaration of declarations) {
    items.push({ kind: "declaration", data: declaration });
  }

  for (let index = 0; index < statusHistory.length; index += 1) {
    items.push({ kind: "status", data: statusHistory[index], index });
  }

  for (const log of auditLogs) {
    items.push({ kind: "audit", data: log });
  }

  return items
    .sort((left, right) => getActivityItemTimestamp(right) - getActivityItemTimestamp(left))
    .slice(0, limit);
}

export function getDisasterActivityTotalCount(
  dashboard: OperationsDisasterDashboard,
  includeAudit: boolean,
): number {
  const declarations = dashboard.declarations?.length ?? 0;
  const statusHistory = dashboard.status_history?.length ?? 0;
  const auditLogs = includeAudit ? (dashboard.recent_audit_logs?.length ?? 0) : 0;
  return declarations + statusHistory + auditLogs;
}

export function hasDisasterActivity(
  dashboard: OperationsDisasterDashboard,
  includeAudit: boolean,
): boolean {
  const declarations = dashboard.declarations ?? [];
  const statusHistory = dashboard.status_history ?? [];
  const auditLogs = includeAudit ? (dashboard.recent_audit_logs ?? []) : [];
  return (
    declarations.length > 0 ||
    statusHistory.length > 0 ||
    auditLogs.length > 0
  );
}

export function DisasterActivityPreviewRow({
  item,
  flattened = false,
}: {
  item: DisasterActivityPreviewItem;
  flattened?: boolean;
}) {
  if (flattened) {
    const { title, subtitle } = getActivityPreviewTitleSubtitle(item);
    return (
      <li className="py-2">
        <p className="truncate text-sm font-semibold text-slate-900">{title}</p>
        <p className="mt-0.5 text-xs text-slate-600">{subtitle}</p>
      </li>
    );
  }

  if (item.kind === "declaration") {
    return (
      <li className="py-2.5">
        <p className="text-sm font-medium text-slate-900">{item.data.title}</p>
        {item.data.issued_at ? (
          <p className="mt-0.5 text-xs text-slate-600">
            Issued {formatBangladeshTime(item.data.issued_at)}
          </p>
        ) : null}
      </li>
    );
  }

  if (item.kind === "status") {
    return (
      <li className="flex items-start justify-between gap-3 py-2.5">
        <div className="min-w-0">
          {item.data.status_code ? (
            <Badge size="compact" tone="neutral">
              {formatBadgeLabel(formatDisasterStatusLabel(item.data.status_code))}
            </Badge>
          ) : null}
          {item.data.note ? (
            <p className="mt-1 line-clamp-2 text-xs text-slate-600">
              {item.data.note}
            </p>
          ) : null}
        </div>
        {item.data.recorded_at ? (
          <span className="shrink-0 text-xs text-slate-500">
            {formatBangladeshTime(item.data.recorded_at)}
          </span>
        ) : null}
      </li>
    );
  }

  return (
    <li className="py-2.5 text-xs text-slate-600">
      <span className="font-medium text-slate-800">
        {item.data.action ?? "Action"}
      </span>
      {item.data.entity_type ? ` · ${item.data.entity_type}` : ""}
      {item.data.created_at ? (
        <span className="mt-0.5 block text-slate-500">
          {formatBangladeshTime(item.data.created_at)}
        </span>
      ) : null}
    </li>
  );
}

function DeclarationRow({ declaration }: { declaration: DisasterDeclaration }) {
  return (
    <li className="rounded-lg border border-slate-100 bg-slate-50 px-3 py-2">
      <p className="text-sm font-medium text-slate-900">{declaration.title}</p>
      {declaration.issued_at ? (
        <p className="mt-0.5 text-xs text-slate-600">
          Issued {formatBangladeshTime(declaration.issued_at)}
        </p>
      ) : null}
    </li>
  );
}

function StatusHistoryRow({
  entry,
}: {
  entry: DisasterStatusHistoryEntry;
}) {
  return (
    <li className="flex items-start justify-between gap-2 rounded-lg border border-slate-100 bg-slate-50 px-3 py-2">
      <div className="min-w-0">
        {entry.status_code ? (
          <Badge size="compact" tone="neutral">
            {formatBadgeLabel(formatDisasterStatusLabel(entry.status_code))}
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
  );
}

function AuditLogRow({ log }: { log: DisasterAuditLog }) {
  return (
    <li className="rounded-lg border border-slate-100 bg-slate-50 px-3 py-2 text-xs text-slate-600">
      <span className="font-medium text-slate-800">{log.action ?? "Action"}</span>
      {log.entity_type ? ` · ${log.entity_type}` : ""}
      {log.created_at ? (
        <span className="mt-0.5 block text-slate-500">
          {formatBangladeshTime(log.created_at)}
        </span>
      ) : null}
    </li>
  );
}

export function DisasterActivitySections({
  dashboard,
  includeAudit = true,
}: {
  dashboard: OperationsDisasterDashboard;
  includeAudit?: boolean;
}) {
  const declarations = dashboard.declarations ?? [];
  const statusHistory = dashboard.status_history ?? [];
  const auditLogs = includeAudit ? (dashboard.recent_audit_logs ?? []) : [];

  return (
    <div className="space-y-4">
      <section>
        <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
          Declarations
        </h4>
        {declarations.length === 0 ? (
          <p className="mt-2 text-sm text-slate-600">No declarations recorded.</p>
        ) : (
          <ul className="mt-2 space-y-1.5">
            {declarations.map((declaration) => (
              <DeclarationRow
                key={declaration.public_uuid}
                declaration={declaration}
              />
            ))}
          </ul>
        )}
      </section>

      <section>
        <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
          Status History
        </h4>
        {statusHistory.length === 0 ? (
          <p className="mt-2 text-sm text-slate-600">No status history recorded.</p>
        ) : (
          <ul className="mt-2 space-y-1.5">
            {statusHistory.map((entry, index) => (
              <StatusHistoryRow
                key={`${entry.status_code}-${entry.recorded_at}-${index}`}
                entry={entry}
              />
            ))}
          </ul>
        )}
      </section>

      {includeAudit ? (
        <section>
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            Recent Audit Logs
          </h4>
          {auditLogs.length === 0 ? (
            <p className="mt-2 text-sm text-slate-600">No audit logs recorded.</p>
          ) : (
            <ul className="mt-2 space-y-1.5">
              {auditLogs.map((log) => (
                <AuditLogRow key={log.id ?? `${log.action}-${log.created_at}`} log={log} />
              ))}
            </ul>
          )}
        </section>
      ) : null}
    </div>
  );
}
