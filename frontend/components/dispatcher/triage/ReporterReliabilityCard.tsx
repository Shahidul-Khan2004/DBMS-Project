"use client";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { formatRiskLevelLabel } from "@/lib/reporter-risk-api";
import type { ReporterRiskSummary } from "@/types/reporter-risk";

type ReporterReliabilityCardProps = {
  reporterRisk: ReporterRiskSummary | null;
  loading?: boolean;
  onRecordVerification?: () => void;
  showRecordButton?: boolean;
};

function riskBadgeTone(level: string): "high" | "medium" | "low" {
  if (level === "high") return "high";
  if (level === "medium") return "medium";
  return "low";
}

export function ReporterReliabilityCard({
  reporterRisk,
  loading = false,
  onRecordVerification,
  showRecordButton = true,
}: ReporterReliabilityCardProps) {
  if (loading) {
    return (
      <section className="rounded-lg border border-slate-200/90 bg-white p-3 shadow-sm">
        <p className="text-xs text-slate-500">Loading reporter reliability…</p>
      </section>
    );
  }

  if (!reporterRisk) {
    return (
      <section className="rounded-lg border border-slate-200/90 bg-slate-50/80 p-3">
        <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
          Reporter Reliability
        </h4>
        <p className="mt-1 text-sm text-slate-600">
          Anonymous or unlinked reporter — no reliability history available.
        </p>
        {showRecordButton && onRecordVerification ? (
          <Button
            type="button"
            variant="secondary"
            size="sm"
            className="mt-2"
            onClick={onRecordVerification}
          >
            Record Verification
          </Button>
        ) : null}
      </section>
    );
  }

  const isHighRisk = reporterRisk.risk_level === "high";

  return (
    <section className="rounded-lg border border-slate-200/90 bg-white p-3 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wide text-slate-500">
            Reporter Reliability
          </h4>
          <p className="mt-0.5 text-sm font-medium text-slate-900">
            {reporterRisk.reporter_full_name}
          </p>
        </div>
        <Badge tone={riskBadgeTone(reporterRisk.risk_level)} size="compact">
          {formatRiskLevelLabel(reporterRisk.risk_level)} risk
        </Badge>
      </div>

      {isHighRisk ? (
        <p className="mt-2 rounded-md border border-[#B91C1C]/25 bg-[#FEF2F2] px-2.5 py-2 text-xs leading-snug text-[#991B1B]">
          High false-report risk. Verify details carefully before dispatching units.
        </p>
      ) : null}

      <dl className="mt-2 grid grid-cols-2 gap-x-3 gap-y-1 text-xs text-slate-600">
        <div>
          <dt className="text-slate-500">Total reports</dt>
          <dd className="font-medium text-slate-800">{reporterRisk.total_reports}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Reviewed</dt>
          <dd className="font-medium text-slate-800">
            {reporterRisk.reviewed_reports ?? "—"}
          </dd>
        </div>
        <div>
          <dt className="text-slate-500">False alarms</dt>
          <dd className="font-medium text-slate-800">{reporterRisk.false_alarm_reports}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Malicious false</dt>
          <dd className="font-medium text-slate-800">
            {reporterRisk.malicious_false_reports}
          </dd>
        </div>
        <div>
          <dt className="text-slate-500">False (30 days)</dt>
          <dd className="font-medium text-slate-800">{reporterRisk.false_reports_30d}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Account status</dt>
          <dd>
            <Badge tone={reporterRisk.account_status} size="compact">
              {reporterRisk.account_status.replace(/_/g, " ")}
            </Badge>
          </dd>
        </div>
      </dl>

      {showRecordButton && onRecordVerification ? (
        <Button
          type="button"
          variant="secondary"
          size="sm"
          className="mt-3"
          onClick={onRecordVerification}
        >
          Record Verification
        </Button>
      ) : null}
    </section>
  );
}
