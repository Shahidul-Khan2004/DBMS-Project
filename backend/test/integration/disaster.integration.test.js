import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { createIntegrationApp } from "../helpers/testApp.js";
import { isDbAvailable } from "../helpers/dbGate.js";
import { getAdminToken } from "../helpers/authTokens.js";
import { request, jsonHeaders } from "../helpers/http.js";
import pool from "../../src/config/db.js";

const dbUp = await isDbAvailable();

describe("disaster ecosystem integration", { skip: !dbUp }, () => {
  it("creates monitoring disaster, adds upazila, declares, and exposes public summary", async () => {
    const app = createIntegrationApp();
    const adminToken = await getAdminToken(app);

    const createRes = await request(app)
      .post("/operations/disasters")
      .set(jsonHeaders(adminToken))
      .send({
        eventTypeCode: "flood",
        title: "Integration Flood Test",
        severityLevel: "high",
      });
    assert.equal(createRes.status, 201);
    const disasterPublicUuid = createRes.body.disaster.public_uuid;

    const [upazilaRows] = await pool.execute(
      `SELECT id FROM administrative_areas WHERE code = 'BD-UPZ-448' LIMIT 1`,
    );
    const upazilaId = Number(upazilaRows[0].id);

    const areaRes = await request(app)
      .post(`/operations/disasters/${disasterPublicUuid}/affected-areas`)
      .set(jsonHeaders(adminToken))
      .send({
        upazilaAdminAreaIds: [upazilaId],
        assessment: {
          impactLevel: "high",
          estimatedAffectedPeople: 12000,
          shelterSupportRequired: true,
          reliefSupportRequired: true,
        },
      });
    assert.equal(areaRes.status, 201);

    const declareRes = await request(app)
      .post(`/operations/disasters/${disasterPublicUuid}/declarations/initial`)
      .set(jsonHeaders(adminToken))
      .send({
        title: "National Flood Declaration",
        publicGuidance: "Evacuate low-lying areas.",
        reason: "Severe flooding across Kurigram Sadar.",
      });
    assert.equal(declareRes.status, 201);

    const publicRes = await request(app).get(`/public/disasters/${disasterPublicUuid}`);
    assert.equal(publicRes.status, 200);
    assert.equal(publicRes.body.disaster.disaster_status, "declared");

    const monitoringOnly = await request(app).get("/public/disasters");
    assert.equal(monitoringOnly.status, 200);
    const found = monitoringOnly.body.disasters.some(
      (d) => d.disaster_public_uuid === disasterPublicUuid,
    );
    assert.equal(found, true);
  });
});
