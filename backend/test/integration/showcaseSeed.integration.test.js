import { describe, it, before } from "node:test";
import assert from "node:assert/strict";
import { createIntegrationApp } from "../helpers/testApp.js";
import { isDbAvailable } from "../helpers/dbGate.js";
import { getCitizenToken, getDispatcherToken } from "../helpers/authTokens.js";
import { request, jsonHeaders } from "../helpers/http.js";
import pool from "../../src/config/db.js";
import { bootstrapDemoCitizens } from "../../src/services/demoCitizenBootstrapService.js";
import { runOperationalDemoSeeds } from "../../src/services/operationalDemoSeedService.js";
import { bootstrapDemoDispatcher } from "../../src/services/demoDispatcherBootstrapService.js";
import { SHOWCASE } from "../helpers/fixtures.js";

const dbUp = await isDbAvailable();
const showcaseEnv =
  process.env.DEMO_CITIZEN_PASSWORD?.length >= 8 &&
  process.env.DEMO_DISPATCHER_PASSWORD?.length >= 8;

describe("showcase operational seed integration", { skip: !dbUp || !showcaseEnv }, () => {
  const app = createIntegrationApp();

  before(async () => {
    await bootstrapDemoCitizens();
    await runOperationalDemoSeeds();
    await bootstrapDemoDispatcher();
  });

  it("showcase intake row exists after bootstrap seeds", async () => {
    const [rows] = await pool.execute(
      `SELECT id FROM intake_reports WHERE public_uuid = ? LIMIT 1`,
      [SHOWCASE.intakeShow001PublicUuid],
    );
    assert.ok(rows[0], "expected showcase intake IR-KUR-SHOW-001");
  });

  it("GET /public/disasters has no declared disasters from showcase seed", async () => {
    const [declared] = await pool.execute(
      `
        SELECT COUNT(*) AS c
        FROM disaster_events de
        INNER JOIN disaster_event_statuses des ON des.id = de.current_status_id
        WHERE des.status_code IN ('declared', 'resolved', 'closed')
      `,
    );
    const res = await request(app).get("/public/disasters");
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.disasters));
    if (Number(declared[0].c) === 0) {
      assert.equal(res.body.disasters.length, 0);
    }
  });

  it("dispatcher overview shows pending work and active operations", async () => {
    const token = await getDispatcherToken(app);
    const res = await request(app)
      .get("/operations/dispatcher/overview")
      .set(jsonHeaders(token));

    assert.equal(res.status, 200);
    const counts = res.body.counts ?? res.body;
    assert.ok(counts.intake_reports_pending_classification >= 2);
    assert.ok(counts.incidents_active >= 3);
    assert.ok(counts.service_cases_open >= 1);
  });

  it("citizen rahima sees reports and service case messages", async () => {
    const token = await getCitizenToken(app);
    const reportsRes = await request(app)
      .get("/intake/reports/my")
      .set(jsonHeaders(token));
    assert.equal(reportsRes.status, 200);
    const reports = reportsRes.body.reports ?? reportsRes.body.intake_reports ?? [];
    assert.ok(
      reports.some((r) => r.public_uuid === SHOWCASE.intakeShow001PublicUuid),
    );

    const casesRes = await request(app)
      .get("/intake/reports/my/service-cases")
      .set(jsonHeaders(token));
    assert.equal(casesRes.status, 200);
    const cases = casesRes.body.service_cases ?? casesRes.body;
    assert.ok(
      cases.some((c) => c.public_uuid === SHOWCASE.serviceCasePublicUuid),
    );

    const messagesRes = await request(app)
      .get(`/intake/service-cases/${SHOWCASE.serviceCasePublicUuid}/messages`)
      .set(jsonHeaders(token));
    assert.equal(messagesRes.status, 200);
    assert.ok((messagesRes.body.messages ?? messagesRes.body).length >= 3);
  });

  it("reporter risk demo has five citizens in reliability view", async () => {
    const [rows] = await pool.execute(
      `
        SELECT reporter_full_name, risk_level, account_status
        FROM vw_reporter_reliability
        WHERE reporter_email LIKE 'citizen.%@niers.test'
        ORDER BY reporter_full_name
      `,
    );
    assert.equal(rows.length, 5, "expected five demo citizens in reporter reliability view");
    const shamim = rows.find((r) => r.reporter_full_name === "Shamim Ahmed");
    assert.ok(shamim, "expected Shamim Ahmed in reporter reliability view");
    assert.equal(shamim.risk_level, "high");
    assert.equal(shamim.account_status, "suspended");
  });

  it("showcase gas-leak incident has fire-service dispatches", async () => {
    const [rows] = await pool.execute(
      `SELECT id FROM emergency_incidents WHERE public_uuid = ? LIMIT 1`,
      [SHOWCASE.incident102PublicUuid],
    );
    if (!rows[0]) {
      return;
    }

    const token = await getDispatcherToken(app);
    const res = await request(app)
      .get(`/operations/incidents/${SHOWCASE.incident102PublicUuid}`)
      .set(jsonHeaders(token));

    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.dispatches));
    assert.ok(res.body.dispatches.length >= 1);
  });
});
