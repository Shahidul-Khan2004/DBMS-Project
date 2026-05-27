import assert from "node:assert/strict";
import { describe, it } from "node:test";
import pool from "../../src/config/db.js";
import { isDbAvailable } from "../helpers/dbGate.js";

const dbUp = await isDbAvailable();
import { request, jsonHeaders } from "../helpers/http.js";
import { createIntegrationApp } from "../helpers/testApp.js";
import { getAgencyRepToken } from "../helpers/authTokens.js";
import { SEED } from "../helpers/fixtures.js";

describe("agency integration", { skip: !dbUp }, () => {

  const app = createIntegrationApp();

  async function skipIfNoDemoRep() {
    const [users] = await pool.execute(
      `SELECT id FROM users WHERE email = ? LIMIT 1`,
      [SEED.fireRepEmail],
    );
    return !users[0];
  }

  it("GET /agency/me returns agency context counts", async () => {
    if (await skipIfNoDemoRep()) {
      return;
    }

    const token = await getAgencyRepToken(app);
    const res = await request(app).get("/agency/me").set(jsonHeaders(token));

    assert.equal(res.status, 200);
    assert.equal(res.body.agency?.agency_code, "DHK-FIRE-01");
    assert.equal(typeof res.body.counts?.active_incidents, "number");
  });

  it("GET /agency/incidents returns list", async () => {
    if (await skipIfNoDemoRep()) {
      return;
    }

    const token = await getAgencyRepToken(app);
    const res = await request(app).get("/agency/incidents").set(jsonHeaders(token));

    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.incidents ?? res.body));
  });

  it("GET /agency/incidents/:incidentPublicUuid/response-logs returns agency logs", async () => {
    if (await skipIfNoDemoRep()) {
      return;
    }

    const token = await getAgencyRepToken(app);
    const listRes = await request(app).get("/agency/incidents").set(jsonHeaders(token));
    assert.equal(listRes.status, 200);

    const incidentUuid = listRes.body.incidents?.[0]?.incident_public_uuid;
    if (!incidentUuid) {
      return;
    }

    const res = await request(app)
      .get(`/agency/incidents/${incidentUuid}/response-logs`)
      .set(jsonHeaders(token));

    assert.equal(res.status, 200);
    assert.equal(res.body.incident_public_uuid, incidentUuid);
    assert.ok(Array.isArray(res.body.response_logs));
  });

  it("GET /agency/dispatches returns list", async () => {
    if (await skipIfNoDemoRep()) {
      return;
    }

    const token = await getAgencyRepToken(app);
    const res = await request(app).get("/agency/dispatches").set(jsonHeaders(token));

    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.dispatches ?? res.body));
  });

  it("loads demo fire representative membership from seed", async () => {
    const [users] = await pool.execute(
      `SELECT id FROM users WHERE email = ? LIMIT 1`,
      [SEED.fireRepEmail],
    );
    if (!users[0]) {
      return;
    }

    const [rows] = await pool.execute(
      `SELECT a.agency_code, am.membership_role, am.membership_status
       FROM agency_memberships am
       INNER JOIN agencies a ON a.id = am.agency_id
       WHERE am.user_id = ? AND am.membership_status = 'active'
       LIMIT 1`,
      [users[0].id],
    );

    assert.equal(rows[0]?.agency_code, "DHK-FIRE-01");
    assert.equal(rows[0]?.membership_role, "representative");
    assert.equal(rows[0]?.membership_status, "active");
  });
});
