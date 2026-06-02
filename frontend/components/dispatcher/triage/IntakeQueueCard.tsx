import { IntakeStatusBadge } from "@/components/dispatcher/triage/IntakeStatusBadge";
import { getIntakeCardAccent } from "@/components/dispatcher/intake/intakeStatusStyles";
import { getDispatcherSelectableRowClasses } from "@/components/dispatcher/listRowHoverStyles";
import type { IntakeQueueItem } from "@/components/dispatcher/triage/types";

interface IntakeQueueCardProps {
  item: IntakeQueueItem;
  selected: boolean;
  onSelect: (id: string) => void;
}

export function IntakeQueueCard({ item, selected, onSelect }: IntakeQueueCardProps) {
  return (
    <button
      type="button"
      onClick={() => onSelect(item.id)}
      className={`min-w-0 w-full overflow-hidden rounded-xl border p-2.5 text-left ${getIntakeCardAccent(item.status)} ${getDispatcherSelectableRowClasses({ selected, variant: "card" })}`}    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0 flex-1">
          <IntakeStatusBadge status={item.status} />
        </div>
        <span className="shrink-0 text-xs text-slate-500">{item.ageLabel}</span>
      </div>
      <p className="mt-1.5 min-w-0 truncate text-sm font-semibold text-slate-900">
        {item.summary}
      </p>
      <p className="mt-1 flex min-w-0 items-center gap-1 text-xs text-slate-600">
        <span className="min-w-0 truncate">{item.category}</span>
        <span className="shrink-0 text-slate-400" aria-hidden>
          ·
        </span>
        <span className="min-w-0 flex-1 truncate">{item.location.addressText}</span>
      </p>
    </button>
  );
}
