export type ArchiveRecordType = "incidents" | "service_cases";

export type ArchiveFinalState = "resolved" | "closed" | "cancelled";

export type ArchivePartialStreamError = {
  stream: "closed" | "escalated";
  message: string;
} | null;
