import type { ArchiveFinalState, ArchiveRecordType } from "@/components/dispatcher/archive/types";

export const ARCHIVE_LIST_LIMIT = 50;

export const ARCHIVE_RECORD_TYPE_OPTIONS: ReadonlyArray<{
  value: ArchiveRecordType;
  label: string;
}> = [
  { value: "incidents", label: "Incidents" },
  { value: "service_cases", label: "Service Cases" },
];

export const ARCHIVE_FINAL_STATE_OPTIONS: ReadonlyArray<{
  value: ArchiveFinalState;
  label: string;
}> = [
  { value: "resolved", label: "Resolved" },
  { value: "closed", label: "Closed" },
  { value: "cancelled", label: "Cancelled" },
];

export function getArchiveFinalStateHelperText(
  recordType: ArchiveRecordType,
  finalState: ArchiveFinalState,
): string {
  if (recordType === "incidents") {
    switch (finalState) {
      case "resolved":
        return "Response completed successfully.";
      case "closed":
        return "Incident record closed after final review.";
      case "cancelled":
        return "Incident workflow cancelled before completion.";
    }
  }

  switch (finalState) {
    case "resolved":
      return "Citizen issue handled and case response completed.";
    case "closed":
      return "Case record closed after final review. Includes escalated cases.";
    case "cancelled":
      return "Case workflow cancelled before completion.";
  }
}

export function getArchiveEmptyStateMessage(
  recordType: ArchiveRecordType,
  finalState: ArchiveFinalState,
): string {
  if (recordType === "incidents") {
    switch (finalState) {
      case "resolved":
        return "No resolved incidents found.";
      case "closed":
        return "No closed incidents found.";
      case "cancelled":
        return "No cancelled incidents found.";
    }
  }

  switch (finalState) {
    case "resolved":
      return "No resolved service cases found.";
    case "closed":
      return "No closed or escalated service cases found.";
    case "cancelled":
      return "No cancelled service cases found.";
  }
}
