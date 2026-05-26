import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { integrationSkipMessage, isDbAvailable } from "../helpers/dbGate.js";

const dbUp = await isDbAvailable();
import { request, jsonHeaders } from "../helpers/http.js";
import { createIntegrationApp } from "../helpers/testApp.js";
import { getAdminToken } from "../helpers/authTokens.js";

describe("admin integration", { skip: !dbUp }, () => {
  it(integrationSkipMessage(), { skip: true });

  const app = createIntegrationApp();

  it("GET /admin/agencies returns pagination metadata", async () => {
    const token = await getAdminToken(app);
    const res = await request(app).get("/admin/agencies").set(jsonHeaders(token));

    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.agencies));
    assert.equal(typeof res.body.total, "number");
    assert.equal(typeof res.body.limit, "number");
  });
});
