import type {
  EmergencyDraft,
  IntakeQueueItem,
  LinkDraft,
  ServiceCaseDraft,
} from "@/components/dispatcher/triage/types";

export function createServiceCaseDraft(item: IntakeQueueItem): ServiceCaseDraft {
  return {
    title: item.summary,
    description: "",
    priority: "medium",
  };
}

export function createEmergencyDraft(item: IntakeQueueItem): EmergencyDraft {
  return {
    severity: "high",
    title: item.summary,
    description: item.description.trim(),
  };
}

export function createLinkDraft(): LinkDraft {
  return {
    incidentId: "",
    linkType: "supporting_report",
    note: "",
  };
}

let mockCodeCounter = 142;

export function nextMockCaseCode(): string {
  mockCodeCounter += 1;
  return `SC-2026-${String(mockCodeCounter).padStart(4, "0")}`;
}

export function nextMockIncidentCode(): string {
  mockCodeCounter += 1;
  return `INC-2026-${String(mockCodeCounter).padStart(4, "0")}`;
}
