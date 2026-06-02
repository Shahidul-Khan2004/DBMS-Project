import { z } from "zod";
import validate from "./validator.js";

const uuid = z.string().uuid();

export const validateDisasterUuidParam = validate(
  "disasterUuidParam",
  z.object({ disasterPublicUuid: uuid }),
  "params",
);

export const validateCreateDisaster = validate(
  "createDisaster",
  z.object({
    eventTypeCode: z.string().min(1),
    title: z.string().min(1).max(255),
    description: z.string().optional(),
    severityLevel: z
      .enum(["low", "medium", "high", "critical", "national"])
      .optional(),
    startedAt: z.string().datetime().optional(),
  }),
);

export const validateDisasterStatusPatch = validate(
  "disasterStatusPatch",
  z.object({
    statusCode: z.enum(["resolved", "closed", "cancelled"]),
    note: z.string().max(500).optional(),
  }),
);

export const validateAddAffectedAreas = validate(
  "addAffectedAreas",
  z
    .object({
      upazilaAdminAreaIds: z.array(z.number().int().positive()).optional(),
      districtAdminAreaId: z.number().int().positive().optional(),
      assessment: z
        .object({
          impactLevel: z.enum(["low", "medium", "high", "severe"]).optional(),
          estimatedAffectedPeople: z.number().int().nonnegative().optional(),
          shelterSupportRequired: z.boolean().optional(),
          reliefSupportRequired: z.boolean().optional(),
          assessmentNote: z.string().max(1000).optional(),
        })
        .optional(),
    })
    .refine(
      (d) =>
        (d.upazilaAdminAreaIds?.length ?? 0) > 0 || d.districtAdminAreaId != null,
      { message: "Provide upazilaAdminAreaIds or districtAdminAreaId" },
    ),
);

export const validateAffectedAreaAssessment = validate(
  "affectedAreaAssessment",
  z.object({
    impactLevel: z.enum(["low", "medium", "high", "severe"]),
    estimatedAffectedPeople: z.number().int().nonnegative().optional(),
    shelterSupportRequired: z.boolean(),
    reliefSupportRequired: z.boolean(),
    assessmentNote: z.string().max(1000).optional(),
  }),
);

export const validateAssignResponsibility = validate(
  "assignResponsibility",
  z.object({
    agencyPublicUuid: uuid,
    responsibilityType: z.enum([
      "coordination",
      "shelter_management",
      "relief_management",
      "medical_support",
      "security_support",
      "rescue_support",
    ]),
    isLead: z.boolean().optional(),
  }),
);

export const validateInitialDeclaration = validate(
  "initialDeclaration",
  z.object({
    title: z.string().min(1).max(255),
    publicGuidance: z.string().optional(),
    legalReference: z.string().max(255).optional(),
    reason: z.string().min(1).max(1000),
  }),
);

export const validateDeclarationAmendment = validate(
  "declarationAmendment",
  z.object({
    title: z.string().min(1).max(255),
    publicGuidance: z.string().optional(),
    legalReference: z.string().max(255).optional(),
    reason: z.string().min(1).max(1000),
  }),
);

export const validateLinkIncident = validate(
  "linkIncident",
  z.object({
    incidentPublicUuid: uuid,
    linkNote: z.string().max(500).optional(),
  }),
);

export const validateUnlinkIncident = validate(
  "unlinkIncident",
  z.object({
    reason: z.string().min(1).max(500),
  }),
);

export const validateManualShelterActivation = validate(
  "manualShelterActivation",
  z.object({
    facilityPublicUuid: uuid,
    usableCapacityOverride: z.number().int().positive().optional(),
    manualOverrideNote: z.string().max(1000).optional(),
  }),
);

export const validateManualHubActivation = validate(
  "manualHubActivation",
  z.object({
    facilityPublicUuid: uuid,
    manualOverrideNote: z.string().max(1000).optional(),
  }),
);

export const validateShelterManagingAgency = validate(
  "shelterManagingAgency",
  z.object({ agencyPublicUuid: uuid }),
);

export const validateOccupancySnapshot = validate(
  "occupancySnapshot",
  z.object({ peopleCount: z.number().int().nonnegative() }),
);

export const validateStockReceipt = validate(
  "stockReceipt",
  z.object({
    reliefItemCode: z.string().min(1),
    quantityReceived: z.number().positive(),
    note: z.string().max(500).optional(),
  }),
);

export const validateActivationDeactivation = validate(
  "activationDeactivation",
  z.object({ note: z.string().max(500).optional() }),
);

export const validateCreateReliefRequest = validate(
  "createReliefRequest",
  z.object({
    shelterActivationPublicUuid: uuid,
    requestNote: z.string().max(1000).optional(),
    items: z
      .array(
        z.object({
          reliefItemCode: z.string().min(1),
          quantityRequested: z.number().positive(),
        }),
      )
      .min(1),
  }),
);

export const validateReliefRequestAction = validate(
  "reliefRequestAction",
  z.object({ note: z.string().max(500).optional() }),
);

export const validateCreateDistribution = validate(
  "createDistribution",
  z.object({
    reliefRequestPublicUuid: uuid,
    sourceHubActivationPublicUuid: uuid,
    items: z
      .array(
        z.object({
          reliefItemCode: z.string().min(1),
          quantityDelivered: z.number().positive(),
        }),
      )
      .min(1),
    note: z.string().max(500).optional(),
  }),
);

export const validateAdminAreaSearch = validate(
  "adminAreaSearch",
  z.object({
    areaType: z.enum(["district", "upazila"]),
    q: z.string().min(1).max(100),
    limit: z.coerce.number().int().min(1).max(50).optional(),
  }),
  "query",
);
