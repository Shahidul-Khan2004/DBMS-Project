import type { IntakeQueueItem } from "@/components/dispatcher/triage/types";

const INTAKE_STATUS_LABELS: Record<IntakeQueueItem["status"], string> = {
  received: "Awaiting Decision",
  under_review: "Verification Required",
};

export function getIntakeStatusLabel(status: IntakeQueueItem["status"]): string {
  return INTAKE_STATUS_LABELS[status];
}
