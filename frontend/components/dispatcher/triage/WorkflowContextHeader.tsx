import { IntakeStatusBadge } from "@/components/dispatcher/triage/IntakeStatusBadge";
import type { IntakeQueueItem } from "@/components/dispatcher/triage/types";
import { Button } from "@/components/ui/Button";

interface WorkflowContextHeaderProps {
  item: IntakeQueueItem;
  detailsExpanded: boolean;
  onToggleDetails: () => void;
  onBackToRouteOptions: () => void;
  showActions?: boolean;
}

export function WorkflowContextHeader({
  item,
  detailsExpanded,
  onToggleDetails,
  onBackToRouteOptions,
  showActions = true,
}: WorkflowContextHeaderProps) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-start justify-between gap-2">
        <h4 className="min-w-0 flex-1 text-sm font-semibold text-slate-900">
          {item.summary}
        </h4>
        <IntakeStatusBadge status={item.status} />
      </div>
      <p className="min-w-0 truncate text-xs text-slate-600">
        {item.category} · {item.location.addressText}
      </p>
      {showActions ? (
        <div className="flex flex-wrap items-center justify-between gap-2">
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={onToggleDetails}
          >
            {detailsExpanded ? "Hide Report Details" : "View Report Details"}
          </Button>
          <Button
            type="button"
            variant="secondary"
            size="sm"
            onClick={onBackToRouteOptions}
          >
            Back to Route Options
          </Button>
        </div>
      ) : null}
    </div>
  );
}
