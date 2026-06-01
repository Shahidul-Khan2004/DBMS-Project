import validate from "./validator.js";
import {
  adminLinkRepresentativeSchema,
  adminOnboardAgencySchema,
  adminPatchAgencySchema,
  agencyPublicUuidParamSchema,
  membershipPublicUuidParamSchema,
  paginationQuerySchema,
} from "./validationSchemas.js";

export const validateAdminOnboardAgency = validate("admin onboard agency", adminOnboardAgencySchema);
export { validateAdminAgenciesListQuery as validateAdminListAgenciesQuery } from "./geoSort.js";
export const validateAdminAgencyUuidParam = validate(
  "admin agency id",
  agencyPublicUuidParamSchema,
  "params",
);
export const validateAdminPatchAgency = validate("admin patch agency", adminPatchAgencySchema);
export const validateAdminLinkRepresentative = validate(
  "admin link representative",
  adminLinkRepresentativeSchema,
);
export const validateAdminMembershipUuidParam = validate(
  "admin membership id",
  membershipPublicUuidParamSchema,
  "params",
);
