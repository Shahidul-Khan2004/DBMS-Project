import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { describe, it } from "node:test";
import pool from "../../src/config/db.js";
import { isDbAvailable } from "../helpers/dbGate.js";
import { request, jsonHeaders } from "../helpers/http.js";
import { createIntegrationApp } from "../helpers/testApp.js";
import { getAgencyRepToken } from "../helpers/authTokens.js";
import { SEED } from "../helpers/fixtures.js";

const dbUp = await isDbAvailable();

describe("agency disaster integration", { skip: !dbUp }, () => {
  const app = createIntegrationApp();

  async function skipIfNoDemoRep() {
    const [users] = await pool.execute(
      `SELECT id FROM users WHERE email = ? LIMIT 1`,
      [SEED.fireRepEmail],
    );
    return !users[0];
  }

  it("GET /agency/disasters returns list shape", async () => {
    if (await skipIfNoDemoRep()) return;

    const token = await getAgencyRepToken(app);
    const res = await request(app).get("/agency/disasters").set(jsonHeaders(token));

    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.disasters));
    assert.equal(typeof res.body.limit, "number");
    assert.equal(typeof res.body.offset, "number");
  });

  it("GET /agency/disasters/:uuid returns 404 for unknown disaster", async () => {
    if (await skipIfNoDemoRep()) return;

    const token = await getAgencyRepToken(app);
    const res = await request(app)
      .get(`/agency/disasters/${randomUUID()}`)
      .set(jsonHeaders(token));

    assert.equal(res.status, 404);
    assert.equal(res.body.error?.code, "DISASTER_NOT_FOUND");
  });

  it("POST occupancy returns 404 for foreign shelter", async () => {
    if (await skipIfNoDemoRep()) return;

    const token = await getAgencyRepToken(app);
    const res = await request(app)
      .post(
        `/agency/disasters/${randomUUID()}/shelters/${randomUUID()}/occupancy`,
      )
      .set(jsonHeaders(token))
      .send({ peopleCount: 10 });

    assert.ok([404, 422].includes(res.status));
  });

  it("POST relief-request returns 404 for unknown disaster", async () => {
    if (await skipIfNoDemoRep()) return;

    const token = await getAgencyRepToken(app);
    const res = await request(app)
      .post(`/agency/disasters/${randomUUID()}/relief-requests`)
      .set(jsonHeaders(token))
      .send({
        shelterActivationPublicUuid: randomUUID(),
        items: [{ reliefItemCode: "rice", quantityRequested: 10 }],
      });

    assert.equal(res.status, 404);
  });

  it("GET /agency/disasters/:uuid/incidents returns 404 when not in agency", async () => {
    if (await skipIfNoDemoRep()) return;

    const token = await getAgencyRepToken(app);
    const [disasters] = await pool.execute(
      `
        SELECT de.public_uuid
        FROM disaster_events de
        LIMIT 1
      `,
    );
    if (!disasters[0]) return;

    const res = await request(app)
      .get(`/agency/disasters/${disasters[0].public_uuid}/incidents`)
      .set(jsonHeaders(token));

    assert.ok([200, 404].includes(res.status));
    if (res.status === 200) {
      assert.ok(Array.isArray(res.body.incidents));
    } else {
      assert.equal(res.body.error?.code, "DISASTER_NOT_IN_AGENCY");
    }
  });
});
