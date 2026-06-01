import type { RouteMode } from "@/components/dispatcher/triage/types";
import type { SelectedIncidentLocation } from "@/components/dispatcher/incidents/create/types";
import type {
  Gateway999Handoff,
  Gateway999LinkType,
  Gateway999PriorityLevel,
  Gateway999SeverityCode,
} from "@/lib/gateway-999-api";

export type Gateway999RouteChoice = Extract<
  RouteMode,
  "service_case" | "emergency_incident" | "existing_incident"
>;

export type Gateway999IncidentOption = {
  publicUuid: string;
  incidentCode: string;
  title: string;
  categoryLabel: string;
  severity: string;
  status: string;
  reportedAt: string;
  reportedAgeLabel?: string;
  locationText: string;
};

export type Gateway999FormState = {
  callerPhoneNumber: string;
  callStartedAt: string;
  reportedAt: string;
  categoryCode: string;
  summary: string;
  description: string;
  routeMode: RouteMode;
  severityCode: Gateway999SeverityCode | "";
  incidentTitle: string;
  incidentDescription: string;
  incidentPublicUuid: string;
  linkType: Gateway999LinkType;
  linkNote: string;
  priorityLevel: Gateway999PriorityLevel | "";
  selectedLocation: SelectedIncidentLocation | null;
  addressText: string;
  placeName: string;
};

export type Gateway999SubmitLabel =
  | "Select Route to Continue"
  | "Create Emergency Incident"
  | "Link Call to Existing Incident"
  | "Create Service Case";

export type { Gateway999Handoff };
