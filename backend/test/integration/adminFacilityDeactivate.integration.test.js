import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { describe, it } from "node:test";
import { isDbAvailable } from "../helpers/dbGate.js";
import { request, jsonHeaders } from "../helpers/http.js";
import { createIntegrationApp } from "../helpers/testApp.js";
import { getAdminToken } from "../helpers/authTokens.js";

const dbUp = await isDbAvailable();

describe("admin facility deactivate integration", { skip: !dbUp }, () => {
  const app = createIntegrationApp();

  it("deactivates an active facility", async () => {
    const adminToken = await getAdminToken(app);
    const facilityCode = `TEST-DEACT-${randomUUID().slice(0, 8)}`;

    const createRes = await request(app)
      .post("/admin/facilities")
      .set(jsonHeaders(adminToken))
      .send({
        facilityCode,
        name: "Test Deactivate Facility",
        facilityTypeCode: "shelter",
        location: {
          latitude: 25.805,
          longitude: 89.636,
          source: "manual_entry",
        },
      });

    assert.equal(createRes.status, 201, JSON.stringify(createRes.body));
    const facilityPublicUuid = createRes.body.facility?.publicUuid;
    assert.ok(facilityPublicUuid);
    assert.equal(createRes.body.facility?.isActive, true);

    const deactivateRes = await request(app)
      .patch(`/admin/facilities/${facilityPublicUuid}/deactivate`)
      .set(jsonHeaders(adminToken));

    assert.equal(deactivateRes.status, 200, JSON.stringify(deactivateRes.body));
    assert.equal(deactivateRes.body.message, "Facility deactivated");
    assert.equal(deactivateRes.body.facility?.isActive, false);
    assert.equal(deactivateRes.body.facility?.facilityCode, facilityCode);

    const getRes = await request(app)
      .get(`/admin/facilities/${facilityPublicUuid}`)
      .set(jsonHeaders(adminToken));

    assert.equal(getRes.status, 200);
    assert.equal(getRes.body.facility?.isActive, false);

    const duplicateRes = await request(app)
      .patch(`/admin/facilities/${facilityPublicUuid}/deactivate`)
      .set(jsonHeaders(adminToken));

    assert.equal(duplicateRes.status, 409);
    assert.equal(duplicateRes.body.error?.code, "FACILITY_ALREADY_INACTIVE");
  });

  it("returns 404 for unknown facility uuid", async () => {
    const adminToken = await getAdminToken(app);
    const unknownUuid = randomUUID();

    const deactivateRes = await request(app)
      .patch(`/admin/facilities/${unknownUuid}/deactivate`)
      .set(jsonHeaders(adminToken));

    assert.equal(deactivateRes.status, 404);
    assert.equal(deactivateRes.body.error?.code, "FACILITY_NOT_FOUND");
  });
});
