import assert from "node:assert/strict";
import { describe, it } from "node:test";
import pool from "../../src/config/db.js";
import { isDbAvailable } from "../helpers/dbGate.js";

const dbUp = await isDbAvailable();
import { request, jsonHeaders } from "../helpers/http.js";
import { createIntegrationApp } from "../helpers/testApp.js";
import { getAdminToken } from "../helpers/authTokens.js";
import { SEED } from "../helpers/fixtures.js";

describe("operations integration", { skip: !dbUp }, () => {

  const app = createIntegrationApp();

  it("GET /operations/dispatcher/overview returns overview payload", async () => {
    const token = await getAdminToken(app);
    const res = await request(app)
      .get("/operations/dispatcher/overview")
      .set(jsonHeaders(token));

    assert.equal(res.status, 200);
    assert.ok(res.body.overview ?? res.body);
  });

  it("GET /operations/incidents returns list", async () => {
    const token = await getAdminToken(app);
    const res = await request(app).get("/operations/incidents").set(jsonHeaders(token));
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.incidents ?? res.body));
  });

  it("GET /operations/intake-reports returns list", async () => {
    const token = await getAdminToken(app);
    const res = await request(app).get("/operations/intake-reports").set(jsonHeaders(token));
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.intake_reports));
  });

  it("GET /operations/incidents/:incidentPublicUuid returns response state", async () => {
    const [rows] = await pool.execute(
      `SELECT id FROM emergency_incidents WHERE public_uuid = ? LIMIT 1`,
      [SEED.demoIncidentPublicUuid],
    );
    if (!rows[0]) {
      return;
    }

    const token = await getAdminToken(app);
    const res = await request(app)
      .get(`/operations/incidents/${SEED.demoIncidentPublicUuid}`)
      .set(jsonHeaders(token));

    assert.equal(res.status, 200);
    assert.equal(res.body.incident.public_uuid, SEED.demoIncidentPublicUuid);
    assert.ok(Array.isArray(res.body.linked_intake_reports));
    assert.ok(Array.isArray(res.body.timeline_preview));
    assert.ok(Array.isArray(res.body.participating_agencies));
    assert.ok(res.body.participating_agencies.length >= 1);

    const participation = res.body.participating_agencies[0];
    assert.ok(participation.agency_public_uuid);
    assert.ok(participation.agency_name);
    assert.ok(participation.agency_type_code);
    assert.equal(typeof participation.is_lead_agency, "boolean");
    assert.ok(participation.participation_status);
    assert.ok(participation.joined_at);

    assert.ok(Array.isArray(res.body.dispatches));
    assert.ok(res.body.dispatches.length >= 1);

    const dispatch = res.body.dispatches[0];
    assert.ok(dispatch.public_uuid);
    assert.ok(dispatch.unit_public_uuid);
    assert.ok(dispatch.status_code);
    assert.ok(dispatch.priority_level);
    assert.ok("assigned_at" in dispatch);
    assert.ok(dispatch.unit?.public_uuid);
    assert.ok(dispatch.unit?.unit_code);
    assert.ok(dispatch.unit?.unit_name);
    assert.ok(dispatch.owning_agency?.public_uuid);
    assert.ok(dispatch.owning_agency?.agency_name);
    assert.ok(dispatch.owning_agency?.agency_type_code);
  });

  it("GET /operations/incidents/:incidentPublicUuid/notes returns notes list", async () => {
    const [rows] = await pool.execute(
      `SELECT id FROM emergency_incidents WHERE public_uuid = ? LIMIT 1`,
      [SEED.demoIncidentPublicUuid],
    );
    if (!rows[0]) {
      return;
    }

    const token = await getAdminToken(app);
    const res = await request(app)
      .get(`/operations/incidents/${SEED.demoIncidentPublicUuid}/notes`)
      .set(jsonHeaders(token));

    assert.equal(res.status, 200);
    assert.equal(res.body.incident_public_uuid, SEED.demoIncidentPublicUuid);
    assert.ok(Array.isArray(res.body.notes));
    assert.equal(typeof res.body.limit, "number");
    assert.equal(typeof res.body.offset, "number");
  });
});
