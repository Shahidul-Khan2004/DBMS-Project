import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  adminAgenciesListQuerySchema,
  citizenGeoListQuerySchema,
  operationsAgencyWorkloadQuerySchema,
} from "../src/api/validators/geoSort.js";
import { operationsListIntakeReportsQuerySchema } from "../src/api/validators/validationSchemas.js";

describe("geo sort query validation", () => {
  it("requires exactly one near reference when sort=distance_asc", () => {
    const fail = operationsAgencyWorkloadQuerySchema.safeParse({
      sort: "distance_asc",
    });
    assert.equal(fail.success, false);

    const ok = operationsAgencyWorkloadQuerySchema.safeParse({
      sort: "distance_asc",
      nearIncidentPublicUuid: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    });
    assert.equal(ok.success, true);
  });

  it("rejects near reference without sort=distance_asc", () => {
    const fail = adminAgenciesListQuerySchema.safeParse({
      nearFacilityPublicUuid: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    });
    assert.equal(fail.success, false);
  });

  it("rejects includeDistance without distance sort", () => {
    const fail = citizenGeoListQuerySchema.safeParse({
      includeDistance: "true",
    });
    assert.equal(fail.success, false);
  });

  it("allows reported_at sort without near reference on intake list", () => {
    const ok = operationsListIntakeReportsQuerySchema.safeParse({
      sort: "reported_at_desc",
    });
    assert.equal(ok.success, true);
  });

  it("accepts citizen distance sort with nearLocationId", () => {
    const ok = citizenGeoListQuerySchema.safeParse({
      sort: "distance_asc",
      nearLocationId: "42",
      includeDistance: "true",
    });
    assert.equal(ok.success, true);
    assert.equal(ok.data.includeDistance, true);
  });
});
