import validate from "./validator.js";
import { z } from "zod";
import {
  adminAgencyNearKeys,
  agencyUnitsNearKeys,
  citizenNearKeys,
  includeDistanceField,
  nearLocationIdField,
  nearUuidFields,
  withGeoSortRefinements,
} from "./geoSortQuery.js";

const distanceSortField = {
  sort: z.enum(["distance_asc"]).optional(),
};

const distanceSortOnlySchema = withGeoSortRefinements(
  z.object({
    ...distanceSortField,
    ...includeDistanceField,
    ...nearUuidFields,
  }),
  adminAgencyNearKeys,
);

export const operationsAgencyWorkloadQuerySchema = withGeoSortRefinements(
  z.object({
    ...distanceSortField,
    ...includeDistanceField,
    nearIncidentPublicUuid: nearUuidFields.nearIncidentPublicUuid,
  }),
  ["nearIncidentPublicUuid"],
);

const paginationFields = {
  limit: z.coerce.number().int().min(1).max(100).optional(),
  offset: z.coerce.number().int().min(0).optional(),
};

export const adminAgenciesListQuerySchema = withGeoSortRefinements(
  z.object({
    ...paginationFields,
    ...distanceSortField,
    ...includeDistanceField,
    ...nearUuidFields,
  }),
  adminAgencyNearKeys,
);

export const operationsAvailableUnitsGeoQuerySchema = z
  .object({
    incidentPublicUuid: z.uuid({ message: "incidentPublicUuid is required" }),
    sort: z.enum(["distance_asc"]).optional(),
    ...includeDistanceField,
  })
  .superRefine((data, ctx) => {
    if (data.includeDistance === true && data.sort !== "distance_asc") {
      ctx.addIssue({
        code: "custom",
        message: "includeDistance requires sort=distance_asc",
        path: ["includeDistance"],
      });
    }
  });

export const agencyUnitsListQuerySchema = withGeoSortRefinements(
  z.object({
    ...paginationFields,
    ...distanceSortField,
    ...includeDistanceField,
    nearIncidentPublicUuid: nearUuidFields.nearIncidentPublicUuid,
    nearFacilityPublicUuid: nearUuidFields.nearFacilityPublicUuid,
    nearDisasterAffectedAreaPublicUuid: nearUuidFields.nearDisasterAffectedAreaPublicUuid,
  }),
  agencyUnitsNearKeys,
);

export const operationsIncidentsListGeoSchema = withGeoSortRefinements(
  z.object({
    status_code: z.string().trim().optional(),
    reported_after: z.iso.datetime({ offset: true }).optional(),
    reported_before: z.iso.datetime({ offset: true }).optional(),
    limit: z.coerce.number().int().min(1).max(100).optional(),
    offset: z.coerce.number().int().min(0).optional(),
    sort: z.enum(["distance_asc"]).optional(),
    ...includeDistanceField,
    nearIntakeReportPublicUuid: nearUuidFields.nearIntakeReportPublicUuid,
  }),
  ["nearIntakeReportPublicUuid"],
);

export const operationsServiceCasesListGeoSchema = withGeoSortRefinements(
  z.object({
    status: z.string().trim().optional(),
    categoryCode: z.string().trim().optional(),
    assignedTo: z.uuid().optional(),
    limit: z.coerce.number().int().min(1).max(100).optional(),
    offset: z.coerce.number().int().min(0).optional(),
    sort: z.enum(["distance_asc"]).optional(),
    ...includeDistanceField,
    nearIntakeReportPublicUuid: nearUuidFields.nearIntakeReportPublicUuid,
  }),
  ["nearIntakeReportPublicUuid"],
);

export const adminFacilitiesListQuerySchema = distanceSortOnlySchema;

export const operationsDisasterDetailGeoQuerySchema = withGeoSortRefinements(
  z.object({
    ...distanceSortField,
    ...includeDistanceField,
    nearDisasterAffectedAreaPublicUuid:
      nearUuidFields.nearDisasterAffectedAreaPublicUuid,
  }),
  ["nearDisasterAffectedAreaPublicUuid"],
);

export const citizenGeoListQuerySchema = withGeoSortRefinements(
  z.object({
    ...distanceSortField,
    ...includeDistanceField,
    ...nearLocationIdField,
  }),
  citizenNearKeys,
);

export const validateOperationsAgencyWorkloadQuery = validate(
  "operations agency workload query",
  operationsAgencyWorkloadQuerySchema,
  "query",
);

export const validateAdminAgenciesListQuery = validate(
  "admin agencies list query",
  adminAgenciesListQuerySchema,
  "query",
);

export const validateOperationsAvailableUnitsGeoQuery = validate(
  "operations available units query",
  operationsAvailableUnitsGeoQuerySchema,
  "query",
);

export const validateAgencyUnitsListQuery = validate(
  "agency units list query",
  agencyUnitsListQuerySchema,
  "query",
);

export const validateOperationsIncidentsListGeoQuery = validate(
  "operations incidents list query",
  operationsIncidentsListGeoSchema,
  "query",
);

export const validateOperationsServiceCasesListGeoQuery = validate(
  "operations service cases list query",
  operationsServiceCasesListGeoSchema,
  "query",
);

export const validateAdminFacilitiesListQuery = validate(
  "admin facilities list query",
  adminFacilitiesListQuerySchema,
  "query",
);

export const validateOperationsDisasterDetailGeoQuery = validate(
  "operations disaster detail geo query",
  operationsDisasterDetailGeoQuerySchema,
  "query",
);

export const validateCitizenGeoListQuery = validate(
  "citizen geo list query",
  citizenGeoListQuerySchema,
  "query",
);
