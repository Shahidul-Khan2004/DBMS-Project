import assert from "node:assert/strict";
import { describe, it } from "node:test";
import BackendError from "../src/lib/BackendError.js";
import {
  resolveAdminAreaFromCoordinates,
  resolveAdminAreaIdForLocationPayload,
} from "../src/services/adminAreaFromGpsService.js";

async function mockListTree(pool, areaType, parentIds) {
  if (areaType === "division") {
    return [
      { id: 1, parent_area_id: null, name: "Dhaka" },
      { id: 2, parent_area_id: null, name: "Chattagram" },
    ];
  }
  if (areaType === "district" && parentIds?.length) {
    if (parentIds.includes(1)) {
      return [{ id: 10, parent_area_id: 1, name: "Dhaka" }];
    }
    if (parentIds.includes(2)) {
      return [
        { id: 20, parent_area_id: 2, name: "AmbiguousDist" },
        { id: 21, parent_area_id: 2, name: "Other" },
      ];
    }
  }
  if (areaType === "upazila" && parentIds?.includes(10)) {
    return [{ id: 100, parent_area_id: 10, name: "Tejgaon" }];
  }
  if (areaType === "union" && parentIds?.includes(100)) {
    return [{ id: 1000, parent_area_id: 100, name: "West Tejturi Bazar" }];
  }
  return [];
}

describe("resolveAdminAreaFromCoordinates", () => {
  it("returns deepest single match (union)", async () => {
    const fetchFn = async () => ({
      status: 200,
      json: async () => ({
        place: {
          division: "Dhaka",
          district: "Dhaka",
          sub_district: "Tejgaon",
          union: "West Tejturi Bazar",
          address: "x",
        },
      }),
    });
    const r = await resolveAdminAreaFromCoordinates(
      /** @type {any} */ ({}),
      23.76,
      90.39,
      {
        fetchFn,
        barikoiApiKey: "fixture",
        listAdministrativeAreasByTypeUnderParents: mockListTree,
      },
    );
    assert.ok(r);
    assert.equal(r.adminAreaId, 1000);
    assert.equal(r.matchedLevel, "union");
  });

  it("returns district when upazila not in payload", async () => {
    const fetchFn = async () => ({
      status: 200,
      json: async () => ({
        place: {
          division: "Dhaka",
          district: "Dhaka",
          address: "x",
        },
      }),
    });
    const r = await resolveAdminAreaFromCoordinates(
      /** @type {any} */ ({}),
      1,
      2,
      {
        fetchFn,
        barikoiApiKey: "fixture",
        listAdministrativeAreasByTypeUnderParents: mockListTree,
      },
    );
    assert.ok(r);
    assert.equal(r.adminAreaId, 10);
    assert.equal(r.matchedLevel, "district");
  });

  it("returns null when district name matches multiple rows", async () => {
    const fetchFn = async () => ({
      status: 200,
      json: async () => ({
        place: {
          division: "Chattagram",
          district: "AmbiguousDist",
          address: "x",
        },
      }),
    });
    const listAmbiguousDistrict = async (pool, areaType, parentIds) => {
      if (areaType === "division") {
        return [{ id: 2, parent_area_id: null, name: "Chattagram" }];
      }
      if (areaType === "district") {
        return [
          { id: 20, parent_area_id: 2, name: "AmbiguousDist" },
          { id: 21, parent_area_id: 2, name: "AmbiguousDist" },
        ];
      }
      return [];
    };
    const r = await resolveAdminAreaFromCoordinates(
      /** @type {any} */ ({}),
      1,
      2,
      {
        fetchFn,
        barikoiApiKey: "fixture",
        listAdministrativeAreasByTypeUnderParents: listAmbiguousDistrict,
      },
    );
    assert.equal(r, null);
  });

  it("throws when Barikoi rejects the API key (HTTP 403)", async () => {
    const fetchFn = async () => ({
      status: 403,
      json: async () => ({ message: "Invalid API key" }),
    });
    await assert.rejects(
      () =>
        resolveAdminAreaFromCoordinates(
          /** @type {any} */ ({}),
          1,
          2,
          {
            fetchFn,
            barikoiApiKey: "invalid",
            listAdministrativeAreasByTypeUnderParents: mockListTree,
          },
        ),
      (err) =>
        err instanceof BackendError &&
        err.code === "BARIKOI_API_KEY_REJECTED" &&
        err.statusCode === 503 &&
        err.details?.httpStatus === 403,
    );
  });

  it("throws when Barikoi rate or usage limit is hit (HTTP 429)", async () => {
    const fetchFn = async () => ({
      status: 429,
      json: async () => ({ message: "Rate limit" }),
    });
    await assert.rejects(
      () =>
        resolveAdminAreaFromCoordinates(
          /** @type {any} */ ({}),
          1,
          2,
          {
            fetchFn,
            barikoiApiKey: "k",
            listAdministrativeAreasByTypeUnderParents: mockListTree,
          },
        ),
      (err) =>
        err instanceof BackendError &&
        err.code === "BARIKOI_QUOTA_EXCEEDED" &&
        err.statusCode === 503,
    );
  });

  it("returns null when provider has no usable fields", async () => {
    const fetchFn = async () => ({
      status: 200,
      json: async () => ({ place: {} }),
    });
    const r = await resolveAdminAreaFromCoordinates(
      /** @type {any} */ ({}),
      1,
      2,
      {
        fetchFn,
        barikoiApiKey: "fixture",
        listAdministrativeAreasByTypeUnderParents: mockListTree,
      },
    );
    assert.equal(r, null);
  });
});

describe("resolveAdminAreaIdForLocationPayload", () => {
  it("does not call Barikoi when explicit id is set", async () => {
    let called = false;
    const fetchFn = async () => {
      called = true;
      return { status: 200, json: async () => ({}) };
    };
    const out = await resolveAdminAreaIdForLocationPayload({
      explicitAdminAreaId: 99,
      latitude: 1,
      longitude: 2,
      pool: /** @type {any} */ ({}),
      fetchFn,
    });
    assert.equal(out.adminAreaId, 99);
    assert.equal(out.resolutionMeta.adminAreaResolved, false);
    assert.equal(called, false);
  });
});
