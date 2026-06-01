"use client";

import type { ReactNode } from "react";
import Link from "next/link";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import {
  formatServiceCaseCategory,
  formatServiceCaseLocation,
  formatServiceCaseResolutionType,
  formatSourceChannel,
} from "@/lib/service-case-format";
import { formatBangladeshTime } from "@/lib/datetime";
import {
  getServiceCaseStatusLabel,
  isServiceCaseEscalated,
  isServiceCaseFinal,
} from "@/lib/service-case-status";
import type {
  OperationsServiceCase,
  ServiceCaseResolution,
} from "@/types/service-case";

function DetailField({
  label,
  value,
}: {
  label: string;
  value: ReactNode;
}) {
  return (
    <div>
      <dt className="text-xs font-medium text-slate-500">{label}</dt>
      <dd className="mt-0.5 text-sm text-slate-900">{value}</dd>
    </div>
  );
}

type ServiceCaseOverviewTabProps = {
  serviceCase: OperationsServiceCase;
  resolution: ServiceCaseResolution | null | undefined;
  linkedIncidentPublicUuid: string | null;
};

export function ServiceCaseOverviewTab({
  serviceCase,
  resolution,
  linkedIncidentPublicUuid,
}: ServiceCaseOverviewTabProps) {
  const terminal = isServiceCaseFinal(serviceCase.status_code);
  const escalated = isServiceCaseEscalated(serviceCase.status_code);
  const locationText =
    formatServiceCaseLocation(serviceCase.location) ||
    serviceCase.location_text?.trim() ||
    null;
  const sourceChannel = formatSourceChannel(serviceCase.source_channel);

  return (
    <div className="space-y-4">
      {terminal ? (
        <div
          className={`rounded-lg border px-3 py-2.5 text-sm ${
            escalated
              ? "border-[#B91C1C]/25 bg-[#FEF2F2] text-[#991B1B]"
              : "border-slate-200 bg-slate-50 text-slate-800"
          }`}
        >
          <p className="font-medium">
            {escalated
              ? "This case was escalated to an emergency incident."
              : `This case is ${getServiceCaseStatusLabel(serviceCase.status_code).toLowerCase()}.`}
          </p>
          {linkedIncidentPublicUuid ? (
            <p className="mt-2">
              <Link
                href={`/dashboard/dispatcher/incidents/${encodeURIComponent(linkedIncidentPublicUuid)}`}
                className="font-medium text-[#006747] underline-offset-2 hover:underline"
              >
                Open Incident Command
              </Link>
            </p>
          ) : null}
        </div>
      ) : null}

      <div>
        <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
          Description
        </h4>
        <p className="mt-1 whitespace-pre-wrap text-sm leading-6 text-slate-700">
          {serviceCase.description?.trim() || "No description provided."}
        </p>
      </div>

      <dl className="grid gap-3 sm:grid-cols-2">
        <DetailField
          label="Status"
          value={
            <Badge tone={serviceCase.status_code}>
              {getServiceCaseStatusLabel(serviceCase.status_code)}
            </Badge>
          }
        />
        <DetailField
          label="Priority"
          value={formatBadgeLabel(serviceCase.priority_level)}
        />
        <DetailField
          label="Category"
          value={formatServiceCaseCategory(serviceCase.category_code)}
        />
        {sourceChannel ? (
          <DetailField label="Source channel" value={sourceChannel} />
        ) : null}
        <DetailField
          label="Created"
          value={formatBangladeshTime(serviceCase.created_at)}
        />
        <DetailField
          label="Last updated"
          value={formatBangladeshTime(serviceCase.last_updated)}
        />
        {serviceCase.intake_report_code ? (
          <DetailField
            label="Originating intake"
            value={
              serviceCase.intake_public_uuid ? (
                <Link
                  href={`/dashboard/dispatcher/intake-reports/${encodeURIComponent(serviceCase.intake_public_uuid)}`}
                  className="font-medium text-[#006747] hover:text-[#002D62]"
                >
                  {serviceCase.intake_report_code}
                </Link>
              ) : (
                serviceCase.intake_report_code
              )
            }
          />
        ) : null}
        {locationText ? (
          <DetailField label="Location" value={locationText} />
        ) : null}
      </dl>

      {resolution ? (
        <div className="rounded-lg border border-slate-200/80 bg-slate-50/80 p-3">
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            Resolution
          </h4>
          <p className="mt-1 text-sm font-medium text-slate-900">
            {formatServiceCaseResolutionType(resolution.resolution_type)}
          </p>
          <p className="mt-2 whitespace-pre-wrap text-sm leading-6 text-slate-700">
            {resolution.resolution_text}
          </p>
          {resolution.resolved_at ? (
            <p className="mt-2 text-xs text-slate-500">
              Resolved {formatBangladeshTime(resolution.resolved_at)}
              {resolution.resolved_by?.full_name
                ? ` · ${resolution.resolved_by.full_name}`
                : ""}
            </p>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}
