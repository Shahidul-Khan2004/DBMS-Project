"use client";

import { formatBadgeLabel } from "@/components/ui/Badge";
import { formatBangladeshTime } from "@/lib/datetime";
import { getServiceCaseStatusLabel } from "@/lib/service-case-status";
import type { ServiceCaseStatusHistoryItem } from "@/types/service-case";

type ServiceCaseStatusHistoryTabProps = {
  statusHistory: ServiceCaseStatusHistoryItem[];
};

export function ServiceCaseStatusHistoryTab({
  statusHistory,
}: ServiceCaseStatusHistoryTabProps) {
  if (statusHistory.length === 0) {
    return (
      <p className="text-sm text-slate-600">No status history recorded yet.</p>
    );
  }

  return (
    <ol className="relative space-y-0 border-l border-slate-200 pl-4">
      {statusHistory.map((item, index) => (
        <li key={item.id ?? `${item.changed_at}-${index}`} className="pb-4 last:pb-0">
          <span
            className="absolute -left-1.5 mt-1.5 h-3 w-3 rounded-full border-2 border-white bg-[#002D62]"
            aria-hidden
          />
          <p className="text-sm font-semibold text-slate-900">
            {getServiceCaseStatusLabel(item.status_code) ||
              formatBadgeLabel(item.status_code)}
          </p>
          <p className="mt-0.5 text-xs text-slate-500">
            {formatBangladeshTime(item.changed_at)}
          </p>
          {item.note?.trim() ? (
            <p className="mt-1.5 text-sm text-slate-700">{item.note}</p>
          ) : null}
          {item.changed_by?.full_name ? (
            <p className="mt-1 text-xs text-slate-500">
              By {item.changed_by.full_name}
            </p>
          ) : null}
        </li>
      ))}
    </ol>
  );
}
