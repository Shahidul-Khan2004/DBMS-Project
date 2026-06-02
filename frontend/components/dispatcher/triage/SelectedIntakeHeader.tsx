import { IntakeStatusBadge } from "@/components/dispatcher/triage/IntakeStatusBadge";
import type { IntakeQueueItem } from "@/components/dispatcher/triage/types";

interface SelectedIntakeHeaderProps {
  item: IntakeQueueItem;
}

export function SelectedIntakeHeader({ item }: SelectedIntakeHeaderProps) {
  return (
    <div>
      <div className="flex items-start justify-between gap-2">
        <IntakeStatusBadge status={item.status} />
        <span className="shrink-0 text-xs text-slate-500">{item.ageLabel}</span>
      </div>
      <h4 className="mt-1 text-sm font-semibold text-slate-900">{item.summary}</h4>
      <p className="mt-0.5 text-xs text-slate-600">
        {item.category} · {item.channel}
      </p>
    </div>
  );
}
