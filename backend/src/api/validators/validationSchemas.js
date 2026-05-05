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
