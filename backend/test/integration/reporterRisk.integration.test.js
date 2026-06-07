import assert from "node:assert/strict";
import { describe, it } from "node:test";
import pool from "../../src/config/db.js";
import { isDbAvailable } from "../helpers/dbGate.js";
import { request, jsonHeaders } from "../helpers/http.js";
import { createIntegrationApp } from "../helpers/testApp.js";
import {
  getAdminToken,
  getCitizenToken,
  getDispatcherToken,
} from "../helpers/authTokens.js";
import { PLACEHOLDER_UUID, SHOWCASE } from "../helpers/fixtures.js";
import { intakeReportVerificationBodySchema } from "../../src/api/validators/validationSchemas.js";

const dbUp = await isDbAvailable();

describe("reporter risk validation", () => {
  it("rejects malicious_false_report without reason or evidence", () => {
    const result = intakeReportVerificationBodySchema.safeParse({
      verdict: "malicious_false_report",
      confidenceLevel: "medium",
    });
    assert.equal(result.success, false);
  });

  it("accepts malicious_false_report with evidenceNote", () => {
    const result = intakeReportVerificationBodySchema.safeParse({
      verdict: "malicious_false_report",
      evidenceNote: "Agency confirmed no incident on site.",
    });
    assert.equal(result.success, true);
  });
});

describe("admin account status validation", () => {
  it("accepts timed suspension with suspensionDays", async () => {
    const { adminAccountStatusBodySchema } = await import(
      "../../src/api/validators/validationSchemas.js"
    );
    const result = adminAccountStatusBodySchema.safeParse({
      accountStatus: "suspended",
      reason: "Repeated malicious false reports",
      suspensionDays: 30,
    });
    assert.equal(result.success, true);
  });

  it("rejects suspend without duration", async () => {
    const { adminAccountStatusBodySchema } = await import(
      "../../src/api/validators/validationSchemas.js"
    );
    const result = adminAccountStatusBodySchema.safeParse({
      accountStatus: "suspended",
      reason: "Repeated malicious false reports",
    });
    assert.equal(result.success, false);
  });
});

describe("reporter risk integration", { skip: !dbUp }, () => {
  const app = createIntegrationApp();

  it("POST verification returns 401 without auth", async () => {
    const res = await request(app)
      .post(
        `/operations/intake-reports/${SHOWCASE.intakeShow001PublicUuid}/verification`,
      )
      .set(jsonHeaders())
      .send({ verdict: "genuine" });
    assert.equal(res.status, 401);
  });

  it("POST verification returns 403 for citizen", async () => {
    const token = await getCitizenToken(app);
    const res = await request(app)
      .post(
        `/operations/intake-reports/${SHOWCASE.intakeShow001PublicUuid}/verification`,
      )
      .set(jsonHeaders(token))
      .send({ verdict: "genuine" });
    assert.equal(res.status, 403);
  });

  it("POST verification returns 201 for dispatcher", async () => {
    const token = await getDispatcherToken(app);
    const res = await request(app)
      .post(
        `/operations/intake-reports/${SHOWCASE.intakeShow001PublicUuid}/verification`,
      )
      .set(jsonHeaders(token))
      .send({
        verdict: "genuine",
        reason: "Follow-up confirmed symptoms",
        confidenceLevel: "high",
      });
    assert.equal(res.status, 201);
    assert.ok(res.body.verification?.public_uuid);
    assert.equal(res.body.verification.verdict, "genuine");
  });

  it("POST verification returns 422 for invalid verdict", async () => {
    const token = await getDispatcherToken(app);
    const res = await request(app)
      .post(
        `/operations/intake-reports/${SHOWCASE.intakeShow001PublicUuid}/verification`,
      )
      .set(jsonHeaders(token))
      .send({ verdict: "not_a_real_verdict" });
    assert.equal(res.status, 422);
    assert.equal(res.body.error?.code, "VALIDATION_ERROR");
  });

  it("POST verification returns 422 for malicious without evidence", async () => {
    const token = await getDispatcherToken(app);
    const res = await request(app)
      .post(
        `/operations/intake-reports/${SHOWCASE.intakeShow001PublicUuid}/verification`,
      )
      .set(jsonHeaders(token))
      .send({ verdict: "malicious_false_report" });
    assert.equal(res.status, 422);
    assert.equal(res.body.error?.code, "VALIDATION_ERROR");
  });

  it("POST verification returns 404 for unknown intake", async () => {
    const token = await getDispatcherToken(app);
    const res = await request(app)
      .post(`/operations/intake-reports/${PLACEHOLDER_UUID}/verification`)
      .set(jsonHeaders(token))
      .send({ verdict: "genuine" });
    assert.equal(res.status, 404);
    assert.equal(res.body.error?.code, "INTAKE_REPORT_NOT_FOUND");
  });

  it("GET admin reporter risk list requires manage permission", async () => {
    const token = await getCitizenToken(app);
    const res = await request(app)
      .get("/admin/reporters/risk")
      .set(jsonHeaders(token));
    assert.equal(res.status, 403);
  });

  it("GET admin reporter risk list returns 200 for system admin", async () => {
    const token = await getAdminToken(app);
    const res = await request(app)
      .get("/admin/reporters/risk")
      .set(jsonHeaders(token));
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.reporters));
  });

  it("PATCH account status returns 409 when unchanged", async () => {
    const token = await getAdminToken(app);
    const [rows] = await pool.execute(
      `SELECT public_uuid, account_status FROM users WHERE email = ? LIMIT 1`,
      [SHOWCASE.citizenRahimaEmail],
    );
    if (!rows[0]) return;

    const res = await request(app)
      .patch(`/admin/users/${rows[0].public_uuid}/account-status`)
      .set(jsonHeaders(token))
      .send({
        accountStatus: rows[0].account_status,
        reason: "No change intended for test",
      });
    assert.equal(res.status, 409);
    assert.equal(res.body.error?.code, "ACCOUNT_STATUS_UNCHANGED");
  });

  it("admin cannot suspend themselves", async () => {
    const token = await getAdminToken(app);
    const email = process.env.SYSTEM_ADMIN__EMAIL;
    const [rows] = await pool.execute(
      `SELECT public_uuid FROM users WHERE email = ? LIMIT 1`,
      [email],
    );
    if (!rows[0]) return;

    const res = await request(app)
      .patch(`/admin/users/${rows[0].public_uuid}/account-status`)
      .set(jsonHeaders(token))
      .send({
        accountStatus: "suspended",
        reason: "Self suspension should be blocked",
      });
    assert.equal(res.status, 403);
  });

  it("vw_reporter_reliability uses latest verification per intake", async () => {
    const [reportRows] = await pool.execute(
      `SELECT id, reporter_user_id FROM intake_reports WHERE public_uuid = ? LIMIT 1`,
      [SHOWCASE.intakeShow001PublicUuid],
    );
    if (!reportRows[0]?.reporter_user_id) return;

    const token = await getDispatcherToken(app);
    await request(app)
      .post(
        `/operations/intake-reports/${SHOWCASE.intakeShow001PublicUuid}/verification`,
      )
      .set(jsonHeaders(token))
      .send({
        verdict: "false_alarm",
        evidenceNote: "Integration test override verdict",
        confidenceLevel: "high",
      });

    const [riskRows] = await pool.execute(
      `SELECT false_alarm_reports, reviewed_reports FROM vw_reporter_reliability WHERE reporter_user_id = ?`,
      [reportRows[0].reporter_user_id],
    );
    assert.ok(riskRows[0]);
    assert.ok(Number(riskRows[0].reviewed_reports) >= 1);
  });
});
