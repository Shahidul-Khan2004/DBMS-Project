import { getIntakeStatusBadgeTone } from "@/components/dispatcher/intake/intakeStatusStyles";
import { getIntakeStatusLabel } from "@/components/dispatcher/triage/intakeStatus";
import type { IntakeQueueItem } from "@/components/dispatcher/triage/types";
import { Badge } from "@/components/ui/Badge";

interface IntakeStatusBadgeProps {
  status: IntakeQueueItem["status"];
}

export function IntakeStatusBadge({ status }: IntakeStatusBadgeProps) {
  return (
    <Badge tone={getIntakeStatusBadgeTone(status)} size="compact">
      {getIntakeStatusLabel(status)}
    </Badge>
  );
}
