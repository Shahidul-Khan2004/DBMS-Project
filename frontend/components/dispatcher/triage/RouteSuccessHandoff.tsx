import type {
  IntakeQueueItem,
  RouteResult,
} from "@/components/dispatcher/triage/types";
import { getSeverityBadgeTone } from "@/components/dispatcher/incidents/severityStyles";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { formatReportStatus } from "@/lib/report-status";

const SUCCESS_PANEL_CLASSES =
  "rounded-lg border border-[#006747]/25 bg-[#F0F7F4] p-2.5 text-sm ring-1 ring-[#006747]/20";

const NEUTRAL_PANEL_CLASSES =
  "rounded-lg border border-slate-200/90 bg-white p-2.5 text-sm shadow-sm";

interface RouteSuccessHandoffProps {
  item: IntakeQueueItem;
  routeResult: RouteResult;
  onOpenDetail: () => void;
  onContinueTriage: () => void;
  continueLabel?: string;
}

export function RouteSuccessHandoff({
  item,
  routeResult,
  onOpenDetail,
  onContinueTriage,
  continueLabel = "Continue Triage",
}: RouteSuccessHandoffProps) {
  if (routeResult.kind === "service_case") {
    return (
      <div className="space-y-3">
        <header>
          <h4 className="text-sm font-semibold text-[#006747]">Service Case Created</h4>
          <p className="mt-1 text-sm font-medium text-slate-800">{item.summary}</p>
        </header>

        <section className={SUCCESS_PANEL_CLASSES}>
          <p className="text-xs font-semibold uppercase tracking-wide text-[#006747]">
            New Service Case
          </p>
          {routeResult.caseCode ? (
            <p className="mt-1 font-mono text-sm font-medium text-slate-900">
              {routeResult.caseCode}
            </p>
          ) : null}
          <p className="mt-1 font-medium text-slate-900">{routeResult.title}</p>
          <p className="mt-2 text-slate-600">
            Status:{" "}
            <Badge tone={routeResult.statusCode} size="compact">
              {formatBadgeLabel(routeResult.statusCode)}
            </Badge>
          </p>
        </section>

        <p className="text-sm text-slate-600">
          This case is ready for dispatcher handling and citizen response.
        </p>

        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="primary" size="sm" onClick={onOpenDetail}>
            Open Service Case
          </Button>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={onContinueTriage}
          >
            {continueLabel}
          </Button>
        </div>
      </div>
    );
  }

  if (routeResult.kind === "emergency_incident") {
    return (
      <div className="space-y-3">
        <header>
          <h4 className="text-sm font-semibold text-slate-900">
            Emergency Incident Created
          </h4>
          <p className="mt-1 text-sm font-medium text-slate-800">{item.summary}</p>
        </header>

        <section className={NEUTRAL_PANEL_CLASSES}>
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            New Emergency Incident
          </p>
          {routeResult.incidentCode ? (
            <p className="mt-1 font-mono text-sm font-medium text-slate-900">
              {routeResult.incidentCode}
            </p>
          ) : null}
          <p className="mt-1 font-medium text-slate-900">{routeResult.title}</p>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <span className="text-slate-600">Severity:</span>
            <Badge tone={getSeverityBadgeTone(routeResult.severity)} size="compact">
              {formatBadgeLabel(routeResult.severity)}
            </Badge>
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-2">
            <span className="text-slate-600">Status:</span>
            <Badge tone={routeResult.statusCode} size="compact">
              {formatBadgeLabel(routeResult.statusCode)}
            </Badge>
          </div>
        </section>

        <p className="text-sm text-slate-600">
          This incident is ready for response coordination.
        </p>

        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="primary" size="sm" onClick={onOpenDetail}>
            Open Incident Command
          </Button>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={onContinueTriage}
          >
            {continueLabel}
          </Button>
        </div>
      </div>
    );
  }

  if (routeResult.kind === "duplicate" || routeResult.kind === "false_report") {
    const title =
      routeResult.kind === "duplicate"
        ? "Report Marked Duplicate"
        : "Report Marked False";

    return (
      <div className="space-y-3">
        <header>
          <h4 className="text-sm font-semibold text-slate-900">{title}</h4>
          <p className="mt-1 text-sm font-medium text-slate-800">{item.summary}</p>
        </header>

        <section className={NEUTRAL_PANEL_CLASSES}>
          <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            Intake Closed
          </p>
          {routeResult.reportCode ? (
            <p className="mt-1 font-mono text-sm font-medium text-slate-900">
              {routeResult.reportCode}
            </p>
          ) : null}
          <p className="mt-2 text-slate-600">
            Status:{" "}
            <Badge tone={routeResult.intakeStatus} size="compact">
              {formatReportStatus(routeResult.intakeStatus)}
            </Badge>
          </p>
        </section>

        <p className="text-sm text-slate-600">
          This report has been removed from the triage queue.
        </p>

        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="primary" size="sm" onClick={onContinueTriage}>
            {continueLabel}
          </Button>
        </div>
      </div>
    );
  }

  if (routeResult.kind === "existing_incident") {
    return (
      <div className="space-y-3">
        <header>
          <h4 className="text-sm font-semibold text-[#006747]">Report Linked to Incident</h4>
          <p className="mt-1 text-sm font-medium text-slate-800">{item.summary}</p>
        </header>

        <section className={SUCCESS_PANEL_CLASSES}>
          <p className="text-xs font-semibold uppercase tracking-wide text-[#006747]">
            Linked to
          </p>
          {routeResult.incidentCode ? (
            <p className="mt-1 font-mono text-sm font-medium text-slate-900">
              {routeResult.incidentCode}
            </p>
          ) : null}
          <p className="mt-1 font-medium text-slate-900">{routeResult.incidentTitle}</p>
        </section>

        <p className="text-sm text-slate-600">
          This report is now linked to the selected active incident.
        </p>

        <div className="flex flex-wrap gap-2">
          <Button type="button" variant="primary" size="sm" onClick={onOpenDetail}>
            Open Incident Command
          </Button>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={onContinueTriage}
          >
            {continueLabel}
          </Button>
        </div>
      </div>
    );
  }

  return null;
}
