import type { IntakeQueueItem } from "@/components/dispatcher/triage/types";

type IntakeStatus = IntakeQueueItem["status"];

const INTAKE_STATUS_BADGE_TONE: Record<IntakeStatus, string> = {
  received: "received",
  under_review: "under_review",
};

const INTAKE_CARD_ACCENT: Record<IntakeStatus, string> = {
  received: "border-l-4 border-l-[#002D62]/50",
  under_review: "border-l-4 border-l-amber-300/90",
};

export const INTAKE_COLUMN_COUNT_CLASSES =
  "bg-amber-50 text-amber-800 ring-1 ring-amber-200";

function normalizeIntakeStatus(status: string | null | undefined): IntakeStatus {
  const key = status?.trim().toLowerCase();
  if (key === "under_review") return "under_review";
  return "received";
}

export function getIntakeStatusBadgeTone(status: string | null | undefined): string {
  return INTAKE_STATUS_BADGE_TONE[normalizeIntakeStatus(status)];
}

export function getIntakeCardAccent(status: string | null | undefined): string {
  return INTAKE_CARD_ACCENT[normalizeIntakeStatus(status)];
}

export function getIntakeColumnCountClasses(): string {
  return INTAKE_COLUMN_COUNT_CLASSES;
}
