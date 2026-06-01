import type { IncidentLocation } from "@/types/incident-command";

export interface ActiveIncidentListItem {
  publicUuid: string;
  incidentCode: string;
  title: string;
  categoryLabel: string;
  /** Backend `severity_code` (e.g. critical, high, medium, low). */
  severity: string;
  /** Backend `status_code` (snake_case). */
  status: string;
  /** Optional; card location is hydrated separately via API. */
  locationText?: string;
  reportedAt: string;
  reportedAgeLabel?: string;
}

export type IncidentCardLocationState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "loaded"; address: string; location: IncidentLocation }
  | { status: "empty" }
  | { status: "error" };

export type ActiveIncidentsStatusFilter = "active_incidents";

export type ActiveIncidentsDateFilter = "all_dates" | "last_24h" | "last_7d";
