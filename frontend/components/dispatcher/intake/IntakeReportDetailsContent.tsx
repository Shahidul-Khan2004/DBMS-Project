"use client";

import { useState } from "react";
import dynamic from "next/dynamic";
import { IntakeStatusBadge } from "@/components/dispatcher/triage/IntakeStatusBadge";
import { ReportedLocationHistoryDialog } from "@/components/dispatcher/triage/ReportedLocationHistoryDialog";
import { LocationInfoBlock } from "@/components/location/LocationInfoBlock";
import { formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { formatBangladeshTime } from "@/lib/datetime";
import { formatIntakeChannelLabel } from "@/lib/incident-source-label";
import { formatIncidentLinkType } from "@/lib/operations-incident-format";
import type { IntakeQueueItem } from "@/components/dispatcher/triage/types";
import type { OperationsIntakeReport } from "@/types/operations-intake";

const ReportedLocationMapPreview = dynamic(
  () =>
    import("@/components/dispatcher/triage/ReportedLocationMapPreview").then(
      (mod) => ({ default: mod.ReportedLocationMapPreview }),
    ),
  {
    ssr: false,
    loading: () => (
      <div className="h-36 w-full animate-pulse rounded-lg bg-slate-100" />
    ),
  },
);

export type IntakeReportLinkContext = {
  linkType?: string | null;
  linkedAt?: string | null;
  incidentTitle?: string | null;
  incidentCode?: string | null;
};

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs font-medium text-slate-500">{label}</dt>
      <dd className="mt-0.5 text-sm text-slate-800">{value}</dd>
    </div>
  );
}

function formatField(value: string | null | undefined) {
  if (!value?.trim()) return "-";
  return formatBadgeLabel(value);
}

function formatLocationText(
  location: OperationsIntakeReport["location"],
): string | null {
  if (!location) return null;
  const address = location.address_text?.trim();
  const place = location.place_name?.trim();
  if (address && place && address !== place) {
    return `${place} — ${address}`;
  }
  return address || place || null;
}

function isQueueIntakeStatus(
  status: string,
): status is IntakeQueueItem["status"] {
  return status === "received" || status === "under_review";
}

function IntakeStatusDisplay({ status }: { status: string }) {
  if (isQueueIntakeStatus(status)) {
    return <IntakeStatusBadge status={status} />;
  }
  return (
    <span className="inline-flex items-center rounded-full bg-slate-100 px-2 py-0.5 text-xs font-semibold text-slate-700 ring-1 ring-slate-200">
      {formatBadgeLabel(status)}
    </span>
  );
}

function ReporterCallerSection({ report }: { report: OperationsIntakeReport }) {
  const reporter = report.reporter;
  const isEmergencyCall = report.channel_code === "emergency_call";

  if (reporter?.is_anonymous) {
    return <p className="text-sm text-slate-700">Anonymous report</p>;
  }

  if (isEmergencyCall) {
    const callerPhone =
      report.emergency_call?.caller_phone_number?.trim() ||
      reporter?.phone_number?.trim() ||
      null;
    const callerName = reporter?.full_name?.trim();

    if (!callerName && !callerPhone) {
      return (
        <p className="text-sm text-slate-500">
          Reporter information is not available in the current response.
        </p>
      );
    }

    return (
      <dl className="grid gap-3">
        {callerName ? (
          <DetailRow label="Caller name" value={callerName} />
        ) : null}
        {callerPhone ? (
          <DetailRow label="Caller phone" value={callerPhone} />
        ) : null}
      </dl>
    );
  }

  const name = reporter?.full_name?.trim();
  const phone = reporter?.phone_number?.trim();
  const email = reporter?.email?.trim();

  if (!name && !phone && !email) {
    return (
      <p className="text-sm text-slate-500">
        Reporter information is not available in the current response.
      </p>
    );
  }

  return (
    <dl className="grid gap-3">
      {name ? <DetailRow label="Name" value={name} /> : null}
      {phone ? <DetailRow label="Phone" value={phone} /> : null}
      {email ? <DetailRow label="Email" value={email} /> : null}
    </dl>
  );
}

function formatIncidentDisplay(
  title: string | null | undefined,
  code: string | null | undefined,
): string {
  const trimmedTitle = title?.trim();
  const trimmedCode = code?.trim();
  if (trimmedTitle && trimmedCode) {
    return `${trimmedTitle} (${trimmedCode})`;
  }
  return trimmedTitle || trimmedCode || "-";
}

export function IntakeReportDetailsContent({
  report,
  context,
  linkContext,
}: {
  report: OperationsIntakeReport;
  context: "command-center" | "incident-command";
  linkContext?: IntakeReportLinkContext | null;
}) {
  const [historyOpen, setHistoryOpen] = useState(false);
  const locationText = formatLocationText(report.location);
  const location = report.location;
  const channelLabel = formatIntakeChannelLabel(report.channel_code);
  const description = report.description?.trim();

  return (
    <>
      <div className="space-y-6">
        <section>
          <h3 className="text-lg font-semibold text-slate-900">{report.summary}</h3>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <IntakeStatusDisplay status={report.intake_status} />
          </div>
          <p className="mt-1 text-xs text-slate-500">{report.report_code}</p>
        </section>

        <section className="border-t border-slate-100 pt-4">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            Report Information
          </h3>
          <dl className="mt-3 grid gap-3 sm:grid-cols-2">
            {report.category_code ? (
              <DetailRow
                label="Category"
                value={formatField(report.category_code)}
              />
            ) : null}
            {report.intake_status ? (
              <DetailRow
                label="Status"
                value={formatField(report.intake_status)}
              />
            ) : null}
            {channelLabel ? (
              <DetailRow label="Source / channel" value={channelLabel} />
            ) : null}
            {report.reported_at ? (
              <DetailRow
                label="Reported"
                value={formatBangladeshTime(report.reported_at)}
              />
            ) : null}
          </dl>
          <div className="mt-4">
            <dt className="text-xs font-medium text-slate-500">Original description</dt>
            <dd className="mt-1 text-sm leading-6 text-slate-700">
              {description || "No additional description provided."}
            </dd>
          </div>
        </section>

        <section className="border-t border-slate-100 pt-4">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            Reporter / Caller
          </h3>
          <div className="mt-3">
            <ReporterCallerSection report={report} />
          </div>
        </section>

        <section className="border-t border-slate-100 pt-4">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            Reported Location
          </h3>
          {locationText ? (
            <div className="mt-3 space-y-3">
              <LocationInfoBlock
                addressText={location?.address_text}
                placeName={location?.place_name}
                latitude={location?.latitude}
                longitude={location?.longitude}
                adminAreaId={location?.admin_area_id}
                fallbackText={locationText}
              />
              {location &&
              Number.isFinite(location.latitude) &&
              Number.isFinite(location.longitude) ? (
                <ReportedLocationMapPreview
                  latitude={location.latitude}
                  longitude={location.longitude}
                  addressText={location.address_text ?? undefined}
                  placeName={location.place_name ?? undefined}
                  previewKey={report.public_uuid}
                />
              ) : null}
              <Button
                type="button"
                variant="secondary"
                size="sm"
                onClick={() => setHistoryOpen(true)}
              >
                View Reported Location History
              </Button>
            </div>
          ) : (
            <p className="mt-3 text-sm text-slate-500">
              No location recorded for this report.
            </p>
          )}
        </section>

        {context === "incident-command" && linkContext ? (
          <section className="border-t border-slate-100 pt-4">
            <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
              Incident Link
            </h3>
            <dl className="mt-3 grid gap-3">
              {linkContext.linkType ? (
                <DetailRow
                  label="Linked As"
                  value={formatIncidentLinkType(linkContext.linkType)}
                />
              ) : null}
              {linkContext.linkedAt ? (
                <DetailRow
                  label="Linked At"
                  value={formatBangladeshTime(linkContext.linkedAt)}
                />
              ) : null}
              {linkContext.incidentTitle || linkContext.incidentCode ? (
                <DetailRow
                  label="Incident"
                  value={formatIncidentDisplay(
                    linkContext.incidentTitle,
                    linkContext.incidentCode,
                  )}
                />
              ) : null}
            </dl>
          </section>
        ) : null}
      </div>

      <ReportedLocationHistoryDialog
        open={historyOpen}
        reportPublicUuid={report.public_uuid}
        reportSummary={report.summary}
        onClose={() => setHistoryOpen(false)}
      />
    </>
  );
}
