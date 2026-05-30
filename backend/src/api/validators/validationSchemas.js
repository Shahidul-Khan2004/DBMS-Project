import { z } from "zod";

export const registerUserSchema = z
  .object({
    email: z.string().trim().pipe(z.email({ message: "Invalid email format" })),
    fullName: z.string().trim().min(1, "Full name is required"),
    phoneNumber: z
      .string()
      .trim()
      .regex(/^\d{11}$/, "Phone number must be exactly 11 digits"),
    password: z.string().min(8, "Password must be at least 8 characters long"),
    rePassword: z.string().min(1, "Please confirm your password"),
  })
  .refine((data) => data.password === data.rePassword, {
    message: "Passwords do not match",
    path: ["rePassword"],
  });

export const loginUserSchema = z.object({
  email: z.string().trim().pipe(z.email({ message: "Invalid email format" })),
  password: z.string().min(1, "Password is required"),
});

export const refreshTokenSchema = z.object({
  refreshToken: z.string().min(1, "Refresh token is required"),
});

const locationSourceEnum = z.enum([
  "user_shared",
  "dispatcher_selected",
  "api_geocoded",
  "manual_entry",
]);

export const locationObjectSchema = z.object({
  latitude: z.number().gte(-90).lte(90),
  longitude: z.number().gte(-180).lte(180),
  address_text: z
    .string()
    .trim()
    .max(255, "address_text must be at most 255 characters")
    .optional(),
  place_name: z.string().trim().max(150).optional(),
  admin_area_id: z.number().int().positive().optional(),
  source: locationSourceEnum.optional(),
});

/** Request body for POST /locations — source is required. */
export const createLocationBodySchema = locationObjectSchema.extend({
  source: locationSourceEnum,
});

export const createIntakeReportSchema = z
  .object({
    channelCode: z.string().trim().min(1, "channelCode is required"),
    categoryCode: z.string().trim().min(1, "categoryCode is required"),
    summary: z
      .string()
      .trim()
      .min(1, "summary is required")
      .max(255, "summary must be at most 255 characters"),
    description: z.string().optional(),
    reportedAt: z.iso.datetime({ offset: true }).optional(),
    location: locationObjectSchema.optional(),
    locationId: z.uuid({ message: "Invalid location id" }).optional(),
  })
  .refine((data) => !(data.location && data.locationId), {
    message: "Provide only one of location or locationId, not both",
    path: ["locationId"],
  })
  .refine((data) => Boolean(data.location || data.locationId), {
    message: "location or locationId is required",
    path: ["location"],
  });

export const classifyServiceCaseSchema = z.object({
  title: z.string().trim().min(1).max(255).optional(),
  description: z.string().optional(),
  priorityLevel: z.enum(["low", "medium", "high", "urgent"]).optional(),
});

export const classifyEmergency999Schema = z.object({
  severityCode: z.enum(["low", "medium", "high", "critical"]),
  incidentTitle: z.string().trim().min(1).max(255).optional(),
  incidentDescription: z.string().optional(),
  callerPhoneNumber: z.string().trim().max(30).optional(),
  callStartedAt: z.iso.datetime({ offset: true }).optional(),
  /** Used by operations promote (no emergency call row). */
  reportedAt: z.iso.datetime({ offset: true }).optional(),
});

export const userRoleAssignmentSchema = z.object({
  roleCode: z
    .string()
    .trim()
    .min(1, "Role code is required")
    .transform((value) => value.toLowerCase()),
});

export const userRoleAssignmentParamsSchema = z.object({
  userId: z.uuid({ message: "Invalid user id" }),
});

export const operationsCreateIncidentSchema = z
  .object({
    categoryCode: z.string().trim().min(1).optional(),
    severityCode: z.enum(["low", "medium", "high", "critical"]),
    title: z.string().trim().min(1).max(255).optional(),
    description: z.string().optional(),
    reportedAt: z.iso.datetime({ offset: true }).optional(),
    location: locationObjectSchema.optional(),
    locationId: z.uuid({ message: "Invalid location id" }).optional(),
    intakeReportPublicUuid: z.uuid().optional(),
  })
  .refine((data) => !(data.location && data.locationId), {
    message: "Provide only one of location or locationId, not both",
    path: ["locationId"],
  })
  .refine(
    (data) =>
      Boolean(data.intakeReportPublicUuid) ||
      Boolean(data.categoryCode && (data.location != null || data.locationId != null)),
    {
      message:
        "Provide intakeReportPublicUuid or categoryCode with a structured location or locationId",
      path: ["categoryCode"],
    },
  )
  .refine(
    (data) =>
      Boolean(data.intakeReportPublicUuid) ||
      Boolean(data.title && data.title.trim().length > 0),
    {
      message: "title is required when creating an incident without linking an intake report",
      path: ["title"],
    },
  );

export const operationsListIntakeReportsQuerySchema = z.object({
  intake_status: z.string().trim().optional(),
  categoryCode: z.string().trim().optional(),
  limit: z.coerce.number().int().min(1).max(100).optional(),
  offset: z.coerce.number().int().min(0).optional(),
  sort: z.enum(["reported_at_desc", "reported_at_asc"]).optional(),
});

export const operationsListIncidentsQuerySchema = z.object({
  status_code: z.string().trim().optional(),
  reported_after: z.iso.datetime({ offset: true }).optional(),
  reported_before: z.iso.datetime({ offset: true }).optional(),
  limit: z.coerce.number().int().min(1).max(100).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

export const operationsPatchIncidentStatusSchema = z.object({
  statusCode: z.string().trim().min(1, "statusCode is required"),
  note: z.string().trim().max(500).optional(),
  outcomeCode: z
    .enum([
      "resolved",
      "false_alarm",
      "duplicate_incident",
      "cancelled",
      "transferred",
      "unresolved",
    ])
    .optional(),
});

export const operationsIncidentNoteSchema = z.object({
  title: z.string().trim().min(1, "note title is required").max(255),
  description: z.string().optional(),
  eventTime: z.iso.datetime({ offset: true }).optional(),
});

export const operationsReportUuidParamSchema = z.object({
  reportPublicUuid: z.uuid({ message: "Invalid report id" }),
});

export const operationsIncidentUuidParamSchema = z.object({
  incidentPublicUuid: z.uuid({ message: "Invalid incident id" }),
});

export const locationPublicUuidParamSchema = z.object({
  publicUuid: z.uuid({ message: "Invalid location id" }),
});

export const intakeReportPublicUuidParamSchema = z.object({
  reportPublicUuid: z.uuid({ message: "Invalid report id" }),
});

export const intakeReportLocationPatchSchema = z
  .object({
    location: locationObjectSchema.optional(),
    locationId: z.uuid({ message: "Invalid location id" }).optional(),
  })
  .refine((data) => Boolean(data.location || data.locationId), {
    message: "Provide either location or locationId",
    path: ["location"],
  })
  .refine((data) => !(data.location && data.locationId), {
    message: "Provide only one of location or locationId, not both",
    path: ["locationId"],
  });

export const operationsLinkIntakeToIncidentSchema = z.object({
  intakeReportPublicUuid: z.uuid({ message: "Invalid report id" }),
  linkType: z
    .enum(["supporting_report", "follow_up_report"])
    .optional()
    .default("supporting_report"),
  note: z.string().trim().max(500).optional(),
});

export const gateway999CreateSchema = z
  .object({
    disposition: z.enum(["service_case", "emergency_incident", "existing_incident"]),
    categoryCode: z.string().trim().min(1, "categoryCode is required"),
    summary: z.string().trim().min(1).max(255),
    description: z.string().optional(),
    reportedAt: z.iso.datetime({ offset: true }).optional(),
    location: locationObjectSchema.optional(),
    locationId: z.uuid({ message: "Invalid location id" }).optional(),
    callerPhoneNumber: z.string().trim().max(30).optional(),
    callStartedAt: z.iso.datetime({ offset: true }).optional(),
    incidentTitle: z.string().trim().min(1).max(255).optional(),
    incidentDescription: z.string().optional(),
    priorityLevel: z.enum(["low", "medium", "high", "urgent"]).optional(),
    severityCode: z.enum(["low", "medium", "high", "critical"]).optional(),
    incidentPublicUuid: z.uuid({ message: "Invalid incident id" }).optional(),
    linkType: z.enum(["supporting_report", "follow_up_report"]).optional(),
    note: z.string().trim().max(500).optional(),
  })
  .refine((data) => !(data.location && data.locationId), {
    message: "Provide only one of location or locationId, not both",
    path: ["locationId"],
  })
  .refine((data) => Boolean(data.location || data.locationId), {
    message: "location or locationId is required",
    path: ["location"],
  })
  .refine(
    (data) =>
      data.disposition === "service_case" ||
      data.disposition === "existing_incident" ||
      (data.disposition === "emergency_incident" && Boolean(data.severityCode)),
    {
      message: "severityCode is required for emergency_incident disposition",
      path: ["severityCode"],
    },
  )
  .refine(
    (data) =>
      data.disposition !== "existing_incident" || Boolean(data.incidentPublicUuid),
    {
      message: "incidentPublicUuid is required for existing_incident disposition",
      path: ["incidentPublicUuid"],
    },
  );

/** Query params for GET /notifications/my — all optional; service applies defaults. */
export const listNotificationsQuerySchema = z.object({
  unread_only: z.preprocess((val) => {
    const v = Array.isArray(val) ? val[0] : val;
    if (v === undefined || v === null || v === "") return undefined;
    if (typeof v === "boolean") return v;
    const s = String(v).toLowerCase().trim();
    if (s === "true" || s === "1" || s === "yes") return true;
    if (s === "false" || s === "0" || s === "no") return false;
    return v;
  }, z.boolean().optional()),
  limit: z.coerce.number().int().min(1).max(100).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

/** Route params for PATCH /notifications/:notificationRecipientId/read */
export const notificationRecipientIdParamSchema = z.object({
  notificationRecipientId: z.coerce.number().int().positive(),
});

/** GET /operations/service-cases */
export const operationsListServiceCasesQuerySchema = z.object({
  status: z.string().trim().optional(),
  categoryCode: z.string().trim().optional(),
  assignedTo: z.uuid({ message: "assignedTo must be a user public UUID" }).optional(),
  limit: z.coerce.number().int().min(1).max(100).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

export const operationsServiceCasePublicUuidParamSchema = z.object({
  publicUuid: z.uuid({ message: "Invalid service case id" }),
});

export const operationsPatchServiceCaseStatusSchema = z.object({
  statusCode: z.string().trim().min(1, "statusCode is required"),
  note: z.string().trim().max(500).optional(),
});

export const operationsPostServiceCaseMessageSchema = z.object({
  title: z.string().trim().min(1, "title is required").max(255),
  description: z.string().optional(),
});

export const operationsPostServiceCaseAssignmentSchema = z.object({
  assignedToUserPublicUuid: z.uuid({ message: "assignedToUserPublicUuid must be a user public UUID" }),
  note: z.string().trim().max(500).optional(),
});

export const operationsPostServiceCaseResolveSchema = z.object({
  resolutionType: z.enum([
    "advice_given",
    "referred_to_facility",
    "escalated",
    "no_action_needed",
    "duplicate",
  ]),
  resolutionText: z.string().trim().min(1, "resolutionText is required"),
  recommendedFacilityId: z.coerce.number().int().positive().optional(),
});

/** POST /intake/reports/:reportPublicUuid/escalate — service case → emergency incident */
export const intakeEscalateServiceCaseToEmergencySchema = classifyEmergency999Schema.extend({
  escalationReason: z.string().trim().min(1, "escalationReason is required").max(1000),
});

export const operationsAddIncidentAgencySchema = z.object({
  agencyPublicUuid: z.uuid({ message: "Invalid agency id" }),
  isLeadAgency: z.boolean().optional().default(false),
});

export const operationsAvailableUnitsQuerySchema = z.object({
  incidentPublicUuid: z.uuid({ message: "incidentPublicUuid is required" }),
});

export const operationsCreateDispatchSchema = z.object({
  unitPublicUuid: z.uuid({ message: "Invalid unit id" }),
  priorityLevel: z.enum(["low", "medium", "high", "critical"]).optional(),
  note: z.string().trim().max(500).optional(),
});

export const operationsDispatchUuidParamSchema = z.object({
  dispatchPublicUuid: z.uuid({ message: "Invalid dispatch id" }),
});

export const operationsPatchDispatchStatusSchema = z.object({
  statusCode: z.enum(["dispatched", "arrived", "completed", "cancelled"]),
  note: z.string().trim().max(500).optional(),
});

export const paginationQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).optional(),
  offset: z.coerce.number().int().min(0).optional(),
});

export const agencyPublicUuidParamSchema = z.object({
  agencyPublicUuid: z.uuid({ message: "Invalid agency id" }),
});

export const membershipPublicUuidParamSchema = z.object({
  membershipPublicUuid: z.uuid({ message: "Invalid membership id" }),
});

export const unitPublicUuidParamSchema = z.object({
  unitPublicUuid: z.uuid({ message: "Invalid unit id" }),
});

export const incidentPublicUuidParamSchema = z.object({
  incidentPublicUuid: z.uuid({ message: "Invalid incident id" }),
});

const adminAgencyPayloadSchema = z.object({
  agency_code: z.string().trim().min(1).max(80),
  name: z.string().trim().min(1).max(180),
  agency_type_code: z.string().trim().min(1),
  description: z.string().trim().max(1000).optional(),
  head_office_location: locationObjectSchema.optional(),
});

export const adminOnboardAgencySchema = z
  .object({
    user_public_uuid: z.uuid({ message: "user_public_uuid must be a user public UUID" }),
    agency_public_uuid: z.uuid({ message: "Invalid agency id" }).optional(),
    agency: adminAgencyPayloadSchema.optional(),
  })
  .refine((data) => Boolean(data.agency_public_uuid) !== Boolean(data.agency), {
    message: "Provide exactly one of agency_public_uuid or agency",
    path: ["agency"],
  });

export const adminPatchAgencySchema = z.object({
  agency_code: z.string().trim().min(1).max(80).optional(),
  name: z.string().trim().min(1).max(180).optional(),
  description: z.string().trim().max(1000).optional(),
  head_office_location: locationObjectSchema.optional(),
});

export const adminLinkRepresentativeSchema = z.object({
  user_public_uuid: z.uuid({ message: "user_public_uuid must be a user public UUID" }),
});

export const agencyCreateUnitSchema = z.object({
  unit_code: z.string().trim().min(1).max(80),
  unit_name: z.string().trim().min(1).max(150),
  unit_type_code: z.string().trim().min(1),
  base_location: locationObjectSchema,
});

export const agencyPatchUnitSchema = z.object({
  unit_code: z.string().trim().min(1).max(80).optional(),
  unit_name: z.string().trim().min(1).max(150).optional(),
  base_location: locationObjectSchema.optional(),
});

export const agencyPatchUnitStatusSchema = z.object({
  status_code: z.enum(["available", "busy"]),
  note: z.string().trim().max(500).optional(),
});

export const agencyCreateResponseLogSchema = z.object({
  log_type: z.enum(["update", "hazard", "casualty", "resource_need", "completion_note"]).optional(),
  message: z.string().trim().min(1, "message is required"),
  dispatch_public_uuid: z.uuid({ message: "Invalid dispatch id" }).optional(),
});

const phoneSchema = z
  .string()
  .trim()
  .regex(/^\d{11}$/, "Phone number must be exactly 11 digits");

export const updateMyProfileSchema = z
  .object({
    fullName: z.string().trim().min(1, "Full name must not be empty").max(150, "Full name must be at most 150 characters").optional(),
    phoneNumber: phoneSchema.optional(),
    secondaryPhoneNumber: z.union([phoneSchema, z.null()]).optional(),
  })
  .refine(
    (data) =>
      data.fullName !== undefined ||
      data.phoneNumber !== undefined ||
      data.secondaryPhoneNumber !== undefined,
    {
      message: "At least one editable field must be provided",
    },
  );