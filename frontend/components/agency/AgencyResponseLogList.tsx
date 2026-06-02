"use client";

import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/StatusState";
import { AgencySkeletonBlock } from "@/components/agency/AgencySkeletonBlock";
import { formatRelativeAge } from "@/lib/format-relative-age";
import type { AgencyResponseLog } from "@/types/agency";

export function AgencyResponseLogList({
  logs,
  loading,
  emptyTitle = "No field updates",
  emptyDescription = "Formal field updates for this incident will appear here.",
}: {
  logs: AgencyResponseLog[];
  loading: boolean;
  emptyTitle?: string;
  emptyDescription?: string;
}) {
  if (loading) {
    return (
      <div className="space-y-3" aria-busy="true">
        <AgencySkeletonBlock className="h-16 w-full" />
        <AgencySkeletonBlock className="h-16 w-full" />
      </div>
    );
  }

  if (logs.length === 0) {
    return (
      <EmptyState title={emptyTitle} description={emptyDescription} />
    );
  }

  return (
    <ul className="space-y-2">
      {logs.map((log) => (
        <li
          key={log.id}
          className="rounded-lg border border-slate-200/90 bg-slate-50/50 px-3 py-2.5"
        >
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone="info">{formatBadgeLabel(log.log_type)}</Badge>
            <span className="text-xs text-slate-500">
              {formatRelativeAge(log.logged_at)}
            </span>
          </div>
          <p className="mt-1.5 text-sm text-slate-800">{log.message}</p>
          {log.dispatch_public_uuid ? (
            <p className="mt-1 text-xs text-slate-500">Linked to a dispatch record</p>
          ) : null}
        </li>
      ))}
    </ul>
  );
}
