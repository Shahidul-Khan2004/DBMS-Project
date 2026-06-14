import { GripVertical } from "lucide-react";
import {
  getIntakeCardAccent,
  getIntakeStatusBadgeTone,
} from "@/components/dispatcher/intake/intakeStatusStyles";
import { AdminAreaInfo } from "@/components/location/AdminAreaInfo";
import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import type { OperationsIntakeReport } from "@/types/operations-intake";

interface CommandCenterIntakeCardProps {
  report: OperationsIntakeReport;
  categoryLabel: string;
  locationLabel: string;
  statusLabel: string;
  ageLabel: string;
  onProcessReport: (publicUuid: string) => void;
}

export function CommandCenterIntakeCard({
  report,
  categoryLabel,
  locationLabel,
  statusLabel,
  ageLabel,
  onProcessReport,
}: CommandCenterIntakeCardProps) {
  const intakeStatus = report.intake_status;

  return (
    <article
      className={`relative rounded-xl border border-slate-200/90 bg-white p-3 shadow-sm ${getIntakeCardAccent(intakeStatus)}`}
    >
      <GripVertical
        className="absolute right-2 top-2.5 h-4 w-4 cursor-grab text-slate-300"
        aria-hidden
      />
      <div className="pr-6">
        <Badge tone={getIntakeStatusBadgeTone(intakeStatus)} size="compact">
          Decision Required
        </Badge>
        <p className="mt-2 text-xs font-medium text-slate-500">{categoryLabel}</p>
        <p className="mt-1 text-sm font-semibold text-slate-900">{report.summary}</p>
        <p className="mt-1 text-xs text-slate-600">{locationLabel}</p>
        <AdminAreaInfo
          adminAreaId={report.location?.admin_area_id}
          className="mt-0.5"
        />
        <p className="mt-1.5 text-xs text-slate-500">
          {statusLabel} · {ageLabel}
        </p>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        <Button
          type="button"
          variant="primary"
          size="sm"
          onClick={() => onProcessReport(report.public_uuid)}
        >
          Process Report
        </Button>
      </div>
    </article>
  );
}
