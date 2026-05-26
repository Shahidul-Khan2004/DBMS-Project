import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { integrationSkipMessage, isDbAvailable } from "../helpers/dbGate.js";

const dbUp = await isDbAvailable();
import { request, jsonHeaders } from "../helpers/http.js";
import { createIntegrationApp } from "../helpers/testApp.js";
import { getAdminToken } from "../helpers/authTokens.js";

describe("operations integration", { skip: !dbUp }, () => {
  it(integrationSkipMessage(), { skip: true });

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
});
