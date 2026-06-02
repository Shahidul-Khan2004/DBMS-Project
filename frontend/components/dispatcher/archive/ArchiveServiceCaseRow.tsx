"use client";

import Link from "next/link";
import { getDispatcherClickableCardRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import {
  getServiceCaseCardAccentMuted,
  getServiceCasePriorityBadgeTone,
} from "@/components/dispatcher/service-cases/priorityStyles";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { formatRelativeAge } from "@/lib/format-relative-age";
import {
  formatServiceCaseCategory,
  formatServiceCaseCodeDisplay,
  getServiceCaseAssignmentDisplay,
} from "@/lib/service-case-format";
import {
  getServiceCaseStatusLabel,
  isServiceCaseEscalated,
} from "@/lib/service-case-status";
import type { OperationsServiceCase } from "@/types/service-case";

interface ArchiveServiceCaseRowProps {
  serviceCase: OperationsServiceCase;
}

export function ArchiveServiceCaseRow({ serviceCase }: ArchiveServiceCaseRowProps) {
  const href = `/dashboard/dispatcher/service-cases/${encodeURIComponent(serviceCase.public_uuid)}`;
  const categoryLabel = formatServiceCaseCategory(serviceCase.category_code);
  const caseCode = formatServiceCaseCodeDisplay(serviceCase.case_code);
  const updatedLabel = formatRelativeAge(serviceCase.last_updated);
  const createdLabel = formatRelativeAge(serviceCase.created_at);
  const assignment = getServiceCaseAssignmentDisplay(serviceCase);
  const escalated = isServiceCaseEscalated(serviceCase.status_code);

  return (
    <li>
      <Link
        href={href}
        className={`group block rounded-xl border px-4 py-3 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-[-2px] focus-visible:outline-[#002D62] ${getServiceCaseCardAccentMuted(serviceCase.priority_level)} ${getDispatcherClickableCardRowClasses()}`}
      >
        <div className="flex flex-col">
          <div className="flex flex-wrap items-center gap-1.5">
            <Badge
              size="compact"
              tone={getServiceCasePriorityBadgeTone(serviceCase.priority_level)}
            >
              {formatBadgeLabel(serviceCase.priority_level)}
            </Badge>
            <Badge size="compact" tone={serviceCase.status_code}>
              {getServiceCaseStatusLabel(serviceCase.status_code)}
            </Badge>
          </div>

          <div className="mt-2 flex flex-col gap-1.5">
            <h3 className="text-sm font-semibold text-slate-900">{serviceCase.title}</h3>

            <p className="text-xs text-slate-600">
              {categoryLabel}
              <span className="text-slate-300"> · </span>
              Updated {updatedLabel}
              <span className="text-slate-300"> · </span>
              Created {createdLabel}
              <span className="text-slate-300"> · </span>
              <span
                className="inline-block max-w-[8rem] truncate font-mono text-slate-500 sm:max-w-[10rem]"
                title={caseCode}
              >
                {caseCode}
              </span>
            </p>

            {escalated ? (
              <p className="text-xs text-[#991B1B]">Emergency incident created</p>
            ) : null}

            <div className="flex items-center justify-between gap-3 pt-0.5">
              {assignment.kind !== "hidden" ? (
                <p className="min-w-0 text-xs text-slate-600">
                  Assignment:{" "}
                  <span className="font-medium text-slate-700">{assignment.label}</span>
                </p>
              ) : (
                <span className="min-w-0 flex-1" aria-hidden />
              )}
              <span className="shrink-0 text-xs font-medium text-slate-400 transition-colors group-hover:text-[#002D62]">
                Review Case →
              </span>
            </div>
          </div>
        </div>
      </Link>
    </li>
  );
}
