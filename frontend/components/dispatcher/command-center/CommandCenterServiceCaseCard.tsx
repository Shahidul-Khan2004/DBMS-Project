import {
  getServiceCaseCardAccent,
  getServiceCasePriorityBadgeTone,
} from "@/components/dispatcher/service-cases/priorityStyles";
import { Badge, formatBadgeLabel } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import type { OperationsServiceCase } from "@/types/service-case";

interface CommandCenterServiceCaseCardProps {
  serviceCase: OperationsServiceCase;
  categoryLabel: string;
  statusLabel: string;
  updatedLabel: string;
  onOpenCase: (publicUuid: string) => void;
}

export function CommandCenterServiceCaseCard({
  serviceCase,
  categoryLabel,
  statusLabel,
  updatedLabel,
  onOpenCase,
}: CommandCenterServiceCaseCardProps) {
  return (
    <article
      className={`rounded-xl border border-slate-200/90 bg-white p-3 shadow-sm ${getServiceCaseCardAccent(serviceCase.priority_level)}`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <Badge
          tone={getServiceCasePriorityBadgeTone(serviceCase.priority_level)}
          size="compact"
        >
          {formatBadgeLabel(serviceCase.priority_level)}
        </Badge>
        <Badge tone={serviceCase.status_code} size="compact">
          {statusLabel}
        </Badge>
      </div>
      <p className="mt-2 text-sm font-semibold text-slate-900">{serviceCase.title}</p>
      <p className="mt-1 text-xs text-slate-600">{categoryLabel}</p>
      <p className="mt-1 text-xs text-slate-500">Updated {updatedLabel}</p>
      <div className="mt-3">
        <Button
          type="button"
          variant="secondary"
          size="sm"
          onClick={() => onOpenCase(serviceCase.public_uuid)}
        >
          Open Case
        </Button>
      </div>
    </article>
  );
}
