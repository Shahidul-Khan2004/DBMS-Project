import { z } from "zod";
import { NEAR_QUERY_KEYS } from "../../repositories/geoReferenceRepo.js";

export const includeDistanceField = {
  includeDistance: z
    .enum(["true", "false", "1", "0"])
    .optional()
    .transform((v) => v === "true" || v === "1"),
};

export const nearUuidFields = {
  nearIncidentPublicUuid: z.uuid().optional(),
  nearIntakeReportPublicUuid: z.uuid().optional(),
  nearServiceCasePublicUuid: z.uuid().optional(),
  nearDisasterAffectedAreaPublicUuid: z.uuid().optional(),
  nearFacilityPublicUuid: z.uuid().optional(),
};

export const nearLocationIdField = {
  nearLocationId: z.coerce.number().int().positive().optional(),
};

const ALL_NEAR_KEYS = [...NEAR_QUERY_KEYS];

/**
 * @param {z.ZodObject} schema
 * @param {string[]} allowedNearKeys subset of NEAR_QUERY_KEYS
 */
export function withGeoSortRefinements(schema, allowedNearKeys = ALL_NEAR_KEYS) {
  return schema.superRefine((data, ctx) => {
    const setNear = allowedNearKeys.filter((key) => data[key] != null);
    const sortIsDistance = data.sort === "distance_asc";
    const wantsDistance = data.includeDistance === true;

    if (sortIsDistance && setNear.length !== 1) {
      ctx.addIssue({
        code: "custom",
        message: "sort=distance_asc requires exactly one near* reference parameter",
        path: ["sort"],
      });
    }

    if (!sortIsDistance && setNear.length > 0) {
      ctx.addIssue({
        code: "custom",
        message: "near* reference parameters require sort=distance_asc",
        path: [setNear[0]],
      });
    }

    if (wantsDistance && !sortIsDistance) {
      ctx.addIssue({
        code: "custom",
        message: "includeDistance requires sort=distance_asc",
        path: ["includeDistance"],
      });
    }

    if (setNear.length > 1) {
      ctx.addIssue({
        code: "custom",
        message: "Only one near* reference parameter may be provided",
        path: [setNear[1]],
      });
    }
  });
}

export const adminAgencyNearKeys = [
  "nearIncidentPublicUuid",
  "nearIntakeReportPublicUuid",
  "nearServiceCasePublicUuid",
  "nearDisasterAffectedAreaPublicUuid",
  "nearFacilityPublicUuid",
];

export const agencyUnitsNearKeys = [
  "nearIncidentPublicUuid",
  "nearFacilityPublicUuid",
  "nearDisasterAffectedAreaPublicUuid",
];

export const citizenNearKeys = ["nearLocationId"];
