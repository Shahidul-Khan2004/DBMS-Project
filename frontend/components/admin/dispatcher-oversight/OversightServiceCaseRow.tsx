"use client";

import Link from "next/link";
import { ChevronRight } from "lucide-react";
import { getDispatcherClickableCardRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { formatBangladeshTime } from "@/lib/datetime";
import {
  formatServiceCaseCategory,
  formatServiceCaseCodeDisplay,
} from "@/lib/service-case-format";
import { getServiceCaseStatusLabel } from "@/lib/service-case-status";
import type { OperationsServiceCase } from "@/types/service-case";

type OversightServiceCaseRowProps = {
  serviceCase: OperationsServiceCase;
};

export function OversightServiceCaseRow({
  serviceCase,
}: OversightServiceCaseRowProps) {
  const href = `/dashboard/dispatcher/service-cases/${encodeURIComponent(serviceCase.public_uuid)}`;
  const assignedUuid = serviceCase.assigned_to_user_public_uuid?.trim();

  return (
    <li>
      <Link
        href={href}
        className={`group flex w-full flex-wrap items-center justify-between gap-3 rounded-xl border px-4 py-3 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[#002D62] ${getDispatcherClickableCardRowClasses()}`}
      >
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-xs text-slate-600">
              {formatServiceCaseCodeDisplay(serviceCase.case_code)}
            </span>
            <Badge size="compact" tone={serviceCase.priority_level}>
              {formatBadgeLabel(serviceCase.priority_level)}
            </Badge>
            <Badge size="compact" tone={serviceCase.status_code}>
              {getServiceCaseStatusLabel(serviceCase.status_code)}
            </Badge>
          </div>
          <p className="mt-1 text-sm font-semibold text-slate-900">
            {serviceCase.title}
          </p>
          <p className="mt-1 text-xs text-slate-600">
            {formatServiceCaseCategory(serviceCase.category_code)}
            {serviceCase.last_updated ? (
              <>
                <span className="text-slate-300"> · </span>
                Updated {formatBangladeshTime(serviceCase.last_updated)}
              </>
            ) : null}
          </p>
          {assignedUuid ? (
            <p className="mt-1 text-xs text-slate-500">
              Assigned user:{" "}
              <span className="font-mono text-slate-600">{assignedUuid}</span>
            </p>
          ) : null}
        </div>
        <span className="flex shrink-0 items-center gap-0.5 text-xs font-medium text-[#002D62]">
          Review case
          <ChevronRight
            className="h-4 w-4 transition-transform group-hover:translate-x-0.5"
            aria-hidden
          />
        </span>
      </Link>
    </li>
  );
}
