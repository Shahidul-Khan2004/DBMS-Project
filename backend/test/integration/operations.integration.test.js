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

  it("DELETE /operations/incidents/:incidentPublicUuid/intake-reports/:reportPublicUuid unlinks a supporting report (happy path)", async () => {
    const [incidentRows] = await pool.execute(
      `SELECT id FROM emergency_incidents WHERE public_uuid = ? LIMIT 1`,
      [SEED.demoIncidentPublicUuid],
    );
    assert.ok(incidentRows[0], "setup: demo incident must exist");

    const token = await getAdminToken(app);

    // Find an intake report not currently linked to this incident
    const [[candidate]] = await pool.execute(
      `
        SELECT ir.public_uuid
        FROM intake_reports ir
        WHERE NOT EXISTS (
          SELECT 1 FROM incident_report_links irl
          INNER JOIN emergency_incidents ei ON ei.id = irl.incident_id
          WHERE irl.intake_report_id = ir.id AND irl.unlinked_at IS NULL AND ei.public_uuid = ?
        )
        LIMIT 1
      `,
      [SEED.demoIncidentPublicUuid],
    );
    assert.ok(candidate?.public_uuid, "setup: must find an unlinked intake report candidate");

    const intakeReportPublicUuid = candidate.public_uuid;

    // Link it to the incident as supporting_report
    const linkRes = await request(app)
      .post(`/operations/incidents/${SEED.demoIncidentPublicUuid}/intake-reports`)
      .set(jsonHeaders(token))
      .send({ intakeReportPublicUuid, linkType: "supporting_report" });
    assert.equal(linkRes.status, 201, `setup: linking failed – ${JSON.stringify(linkRes.body)}`);

    const reason = "testing unlink";
    const res = await request(app)
      .delete(`/operations/incidents/${SEED.demoIncidentPublicUuid}/intake-reports/${intakeReportPublicUuid}`)
      .set(jsonHeaders(token))
      .send({ reason });

    assert.equal(res.status, 200, JSON.stringify(res.body));
    assert.equal(res.body.message, "Intake report unlinked from incident");
    assert.equal(res.body.unlink.intake_report_public_uuid, intakeReportPublicUuid);
    assert.equal(res.body.unlink.intake_status, "under_review");
    assert.ok(res.body.unlink.unlinked_at);
    assert.equal(res.body.unlink.unlink_reason, reason);

    // DB: verify soft-unlink preserved
    const [[row]] = await pool.execute(
      `
        SELECT irl.unlinked_at, irl.unlinked_by_user_id, irl.unlink_reason
        FROM incident_report_links irl
        INNER JOIN intake_reports ir ON ir.id = irl.intake_report_id
        INNER JOIN emergency_incidents ei ON ei.id = irl.incident_id
        WHERE ei.public_uuid = ? AND ir.public_uuid = ?
        LIMIT 1
      `,
      [SEED.demoIncidentPublicUuid, intakeReportPublicUuid],
    );
    assert.ok(row, "expected incident_report_links row to exist");
    assert.ok(row.unlinked_at, "expected unlinked_at to be set");
    assert.ok(row.unlinked_by_user_id, "expected unlinked_by_user_id to be set");
    assert.equal(row.unlink_reason, reason);

    // Incident detail should no longer list the unlinked report
    const incidentRes = await request(app)
      .get(`/operations/incidents/${SEED.demoIncidentPublicUuid}`)
      .set(jsonHeaders(token));
    assert.equal(incidentRes.status, 200);
    const linked = incidentRes.body.linked_intake_reports || [];
    assert.ok(!linked.find((r) => r.intake_public_uuid === intakeReportPublicUuid));
  });

  it("DELETE /operations/incidents/:incidentPublicUuid/intake-reports/:reportPublicUuid returns 409 for primary_report", async () => {
    const [primaryRows] = await pool.execute(
      `
        SELECT ir.public_uuid
        FROM incident_report_links irl
        INNER JOIN intake_reports ir ON ir.id = irl.intake_report_id
        INNER JOIN emergency_incidents ei ON ei.id = irl.incident_id
        WHERE ei.public_uuid = ? AND irl.link_type = 'primary_report' AND irl.unlinked_at IS NULL
        LIMIT 1
      `,
      [SEED.demoIncidentPublicUuid],
    );
    assert.ok(primaryRows[0], "setup: demo incident must have an active primary_report link");

    const primaryReportPublicUuid = primaryRows[0].public_uuid;
    const token = await getAdminToken(app);
    const res = await request(app)
      .delete(`/operations/incidents/${SEED.demoIncidentPublicUuid}/intake-reports/${primaryReportPublicUuid}`)
      .set(jsonHeaders(token))
      .send({ reason: "attempt primary unlink" });

    assert.equal(res.status, 409, JSON.stringify(res.body));
    assert.equal(res.body.error?.code, "PRIMARY_REPORT_UNLINK_NOT_ALLOWED");
  });

  it("DELETE for a non-linked report returns 404 INCIDENT_REPORT_LINK_NOT_FOUND", async () => {
    const [[candidate]] = await pool.execute(
      `
        SELECT public_uuid FROM intake_reports ir
        WHERE NOT EXISTS (
          SELECT 1 FROM incident_report_links irl WHERE irl.intake_report_id = ir.id AND irl.unlinked_at IS NULL
        )
        LIMIT 1
      `,
      [],
    );
    if (!candidate?.public_uuid) {
      assert.fail("setup: must find an intake report with no active incident link");
    }

    const token = await getAdminToken(app);
    const res = await request(app)
      .delete(`/operations/incidents/${SEED.demoIncidentPublicUuid}/intake-reports/${candidate.public_uuid}`)
      .set(jsonHeaders(token))
      .send({ reason: "not linked" });

    assert.equal(res.status, 404, JSON.stringify(res.body));
    assert.equal(res.body.error?.code, "INCIDENT_REPORT_LINK_NOT_FOUND");
  });
});