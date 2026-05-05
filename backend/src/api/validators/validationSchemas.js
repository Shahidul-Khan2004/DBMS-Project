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

const locationObjectSchema = z.object({
  latitude: z.number().gte(-90).lte(90),
  longitude: z.number().gte(-180).lte(180),
  address_text: z.string().trim().min(1),
  place_name: z.string().trim().optional(),
  admin_area_id: z.number().int().positive().optional(),
  source: locationSourceEnum.optional(),
});

export const createIntakeReportSchema = z.object({
  channelCode: z.string().trim().min(1, "channelCode is required"),
  categoryCode: z.string().trim().min(1, "categoryCode is required"),
  summary: z
    .string()
    .trim()
    .min(1, "summary is required")
    .max(255, "summary must be at most 255 characters"),
  description: z.string().optional(),
  urgencyType: z.enum(["non_emergency", "emergency", "unknown"]).optional(),
  reportedAt: z.iso.datetime({ offset: true }).optional(),
  location: z.union([z.string().trim().min(1), locationObjectSchema]).optional(),
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

export const operationsLocationInputSchema = z.union([
  z.string().trim().min(1),
  locationObjectSchema,
]);

export const operationsCreateIncidentSchema = z
  .object({
    categoryCode: z.string().trim().min(1).optional(),
    severityCode: z.enum(["low", "medium", "high", "critical"]),
    title: z.string().trim().min(1).max(255).optional(),
    description: z.string().optional(),
    reportedAt: z.iso.datetime({ offset: true }).optional(),
    location: operationsLocationInputSchema.optional(),
    intakeReportPublicUuid: z.uuid().optional(),
  })
  .refine(
    (data) =>
      Boolean(data.intakeReportPublicUuid) ||
      Boolean(data.categoryCode && data.location != null && data.location !== ""),
    {
      message: "Provide intakeReportPublicUuid or both categoryCode and location",
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
  urgency_type: z.enum(["non_emergency", "emergency", "unknown"]).optional(),
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
