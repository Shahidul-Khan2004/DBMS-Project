import { ApiError, apiPost } from "@/lib/api";

export type Gateway999Disposition =
  | "emergency_incident"
  | "existing_incident"
  | "service_case";

export type Gateway999SeverityCode = "low" | "medium" | "high" | "critical";

export type Gateway999PriorityLevel = "low" | "medium" | "high" | "urgent";

export type Gateway999LinkType = "supporting_report" | "follow_up_report";

export type Gateway999LocationPayload = {
  latitude: number;
  longitude: number;
  address_text?: string;
  place_name?: string;
  admin_area_id?: number;
  source?: "dispatcher_selected";
};

export type Gateway999Payload = {
  disposition: Gateway999Disposition;
  categoryCode: string;
  summary: string;
  description?: string;
  reportedAt?: string;
  location?: Gateway999LocationPayload;
  locationId?: string;
  callerPhoneNumber?: string;
  callStartedAt?: string;
  severityCode?: Gateway999SeverityCode;
  incidentTitle?: string;
  incidentDescription?: string;
  incidentPublicUuid?: string;
  linkType?: Gateway999LinkType;
  note?: string;
  priorityLevel?: Gateway999PriorityLevel;
};

type GatewayEntity = Record<string, unknown>;

export type Gateway999Response = {
  message?: string;
  disposition?: Gateway999Disposition;
  intake?: GatewayEntity;
  emergency_call?: GatewayEntity;
  service_case?: GatewayEntity;
  emergency_incident?: GatewayEntity;
  incident?: GatewayEntity;
  incident_report_link?: GatewayEntity;
  [key: string]: unknown;
};

export type Gateway999HandoffKind =
  | "emergency_incident"
  | "existing_incident"
  | "service_case";

export type Gateway999Handoff = {
  kind: Gateway999HandoffKind;
  message: string;
  routeLabel: string;
  summary: string;
  intakeReportCode?: string;
  entityCode?: string;
  entityTitle?: string;
  publicUuid?: string;
  detailHref?: string;
  missingUuidMessage?: string;
};

function readString(entity: GatewayEntity | undefined, ...keys: string[]): string | undefined {
  if (!entity) return undefined;
  for (const key of keys) {
    const value = entity[key];
    if (typeof value === "string" && value.trim()) {
      return value.trim();
    }
  }
  return undefined;
}

function extractPublicUuid(
  response: Gateway999Response,
  disposition: Gateway999Disposition,
  fallbackIncidentUuid?: string,
): string | undefined {
  if (disposition === "emergency_incident") {
    return (
      readString(response.emergency_incident, "public_uuid", "publicUuid") ??
      readString(response.incident, "public_uuid", "publicUuid")
    );
  }

  if (disposition === "existing_incident") {
    return (
      readString(response.incident_report_link, "incident_public_uuid", "incidentPublicUuid") ??
      fallbackIncidentUuid
    );
  }

  return readString(response.service_case, "public_uuid", "publicUuid");
}

function buildDetailHref(
  kind: Gateway999HandoffKind,
  publicUuid: string | undefined,
): string | undefined {
  if (!publicUuid) return undefined;
  const encoded = encodeURIComponent(publicUuid);
  if (kind === "service_case") {
    return `/dashboard/dispatcher/service-cases/${encoded}`;
  }
  return `/dashboard/dispatcher/incidents/${encoded}`;
}

const ROUTE_LABELS: Record<Gateway999HandoffKind, string> = {
  emergency_incident: "New Emergency Incident",
  existing_incident: "Existing Incident",
  service_case: "Service Case",
};

const SUCCESS_MESSAGES: Record<Gateway999HandoffKind, string> = {
  emergency_incident: "Emergency incident created from 999 intake.",
  existing_incident: "999 call linked to existing incident.",
  service_case: "Service case created from 999 intake.",
};

export function mapGateway999Handoff(
  response: Gateway999Response,
  disposition: Gateway999Disposition,
  summary: string,
  fallbackIncidentUuid?: string,
): Gateway999Handoff {
  const publicUuid = extractPublicUuid(response, disposition, fallbackIncidentUuid);
  const detailHref = buildDetailHref(disposition, publicUuid);

  const intakeReportCode = readString(response.intake, "report_code", "reportCode");

  let entityCode: string | undefined;
  let entityTitle: string | undefined;

  if (disposition === "emergency_incident") {
    entityCode = readString(response.emergency_incident, "incident_code", "incidentCode");
    entityTitle = readString(response.emergency_incident, "title");
  } else if (disposition === "existing_incident") {
    entityCode = readString(
      response.incident_report_link,
      "incident_code",
      "incidentCode",
    );
    entityTitle = readString(response.incident_report_link, "incident_title");
  } else {
    entityCode = readString(response.service_case, "case_code", "caseCode");
    entityTitle = readString(response.service_case, "title");
  }

  return {
    kind: disposition,
    message: SUCCESS_MESSAGES[disposition],
    routeLabel: ROUTE_LABELS[disposition],
    summary,
    intakeReportCode,
    entityCode,
    entityTitle,
    publicUuid,
    detailHref,
    missingUuidMessage: publicUuid
      ? undefined
      : "The record was created, but the detail link could not be built from the response.",
  };
}

export async function submitGateway999Intake(
  payload: Gateway999Payload,
): Promise<Gateway999Response> {
  return apiPost<Gateway999Response, Gateway999Payload>(
    "/operations/gateway/999/intake-and-incident",
    payload,
  );
}

const ERROR_HINTS: Record<string, string> = {
  CATEGORY_REQUIRED: "Choose a category for this call.",
  LOCATION_REQUIRED: "Select a reported location before submitting.",
  EMERGENCY_INCIDENT_REQUIRES_LOCATION: "Select a reported location before submitting.",
  SERVICE_CASE_REQUIRES_LOCATION: "Select a reported location before submitting.",
  INCIDENT_NOT_FOUND: "The selected incident could not be found.",
  INCIDENT_NOT_LINKABLE: "The selected incident cannot accept new reports.",
  INTAKE_ALREADY_LINKED: "This intake is already linked to another record.",
};

export function mapGateway999Error(
  error: unknown,
  fallback = "999 intake submission failed.",
): string {
  if (error instanceof ApiError) {
    const hint = error.code ? ERROR_HINTS[error.code] : undefined;
    const codePrefix = error.code ? `${error.code}: ` : "";
    const details =
      Array.isArray(error.details) && error.details.length > 0
        ? ` Details: ${error.details
            .map((detail) =>
              typeof detail === "string" ? detail : JSON.stringify(detail),
            )
            .join("; ")}`
        : "";
    return `${codePrefix}${error.message}${hint ? ` ${hint}` : ""}${details}`;
  }

  return error instanceof Error ? error.message : fallback;
}
