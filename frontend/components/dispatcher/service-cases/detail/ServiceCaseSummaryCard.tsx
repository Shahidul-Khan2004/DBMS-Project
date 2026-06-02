"use client";

import { MapPin } from "lucide-react";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import {
  formatServiceCaseCategory,
  formatServiceCaseCodeDisplay,
  formatServiceCaseLocation,
  formatSourceChannel,
  getServiceCaseAssignmentSummaryLabel,
} from "@/lib/service-case-format";
import { formatRelativeAge } from "@/lib/format-relative-age";
import { getServiceCaseStatusLabel } from "@/lib/service-case-status";
import type {
  OperationsServiceCase,
  ServiceCaseAssignment,
} from "@/types/service-case";

type ServiceCaseSummaryCardProps = {
  className?: string;
  serviceCase: OperationsServiceCase;
  assignments: ServiceCaseAssignment[];
  canViewOriginalReport?: boolean;
  onViewOriginalReport?: () => void;
};

export function ServiceCaseSummaryCard({
  className = "",
  serviceCase,
  assignments,
  canViewOriginalReport = false,
  onViewOriginalReport,
}: ServiceCaseSummaryCardProps) {
  const categoryLabel = formatServiceCaseCategory(serviceCase.category_code);
  const caseCode = formatServiceCaseCodeDisplay(serviceCase.case_code);
  const updatedLabel = formatRelativeAge(serviceCase.last_updated);
  const assignmentLabel = getServiceCaseAssignmentSummaryLabel(assignments);
  const locationText =
    formatServiceCaseLocation(serviceCase.location) ||
    serviceCase.location_text?.trim() ||
    null;
  const sourceChannelLabel = formatSourceChannel(serviceCase.source_channel);

  const showViewOriginalReport =
    canViewOriginalReport && onViewOriginalReport != null;

  const sectionClasses = [
    "shrink-0 rounded-xl border border-slate-200/90 bg-white p-3 shadow-sm sm:p-4",
    className,
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <section className={sectionClasses}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-sm font-semibold text-slate-900 xl:text-base">
              {serviceCase.title}
            </h1>
            <Badge tone={serviceCase.priority_level}>
              {formatBadgeLabel(serviceCase.priority_level)}
            </Badge>
            <Badge tone={serviceCase.status_code}>
              {getServiceCaseStatusLabel(serviceCase.status_code)}
            </Badge>
          </div>

          <p className="text-sm text-slate-600">
            {categoryLabel}
            <span className="text-slate-300"> · </span>
            <span className="font-medium text-slate-700">{caseCode}</span>
            <span className="text-slate-300"> · </span>
            Updated {updatedLabel}
            {sourceChannelLabel ? (
              <>
                <span className="text-slate-300"> · </span>
                {sourceChannelLabel}
              </>
            ) : null}
          </p>

          {assignmentLabel || locationText ? (
            <div className="flex min-w-0 flex-wrap items-center gap-x-4 gap-y-0.5 text-xs text-slate-600">
              {locationText ? (
                <p className="flex min-w-0 items-center gap-1">
                  <MapPin
                    className="h-3.5 w-3.5 shrink-0 text-slate-400"
                    aria-hidden
                  />
                  <span className="truncate">{locationText}</span>
                </p>
              ) : null}
              {assignmentLabel ? (
                <p>
                  Assignment:{" "}
                  <span className="font-medium text-slate-700">
                    {assignmentLabel}
                  </span>
                </p>
              ) : null}
            </div>
          ) : null}
        </div>

        {showViewOriginalReport ? (
          <div className="hidden shrink-0 xl:block">
            <Button
              type="button"
              variant="secondary"
              size="sm"
              onClick={onViewOriginalReport}
            >
              View Original Report
            </Button>
          </div>
        ) : null}
      </div>

      {showViewOriginalReport ? (
        <div className="mt-3 xl:hidden">
          <Button
            type="button"
            variant="secondary"
            size="sm"
            className="w-full sm:w-auto"
            onClick={onViewOriginalReport}
          >
            View Original Report
          </Button>
        </div>
      ) : null}
    </section>
  );
}
