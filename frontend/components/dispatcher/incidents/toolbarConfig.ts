import type {
  ActiveIncidentsDateFilter,
  ActiveIncidentsStatusFilter,
} from "@/components/dispatcher/incidents/types";

export const ACTIVE_INCIDENTS_STATUS_OPTIONS: {
  value: ActiveIncidentsStatusFilter;
  label: string;
}[] = [{ value: "active_incidents", label: "Active Incidents" }];

export const ACTIVE_INCIDENTS_DATE_OPTIONS: {
  value: ActiveIncidentsDateFilter;
  label: string;
}[] = [
  { value: "all_dates", label: "All Dates" },
  { value: "last_24h", label: "Last 24 Hours" },
  { value: "last_7d", label: "Last 7 Days" },
];
