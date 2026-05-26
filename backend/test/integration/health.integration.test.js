import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { integrationSkipMessage, isDbAvailable } from "../helpers/dbGate.js";
import { request } from "../helpers/http.js";
import { createIntegrationApp } from "../helpers/testApp.js";

const dbUp = await isDbAvailable();

describe("GET /health integration", { skip: !dbUp }, () => {
  it(integrationSkipMessage(), { skip: true });

  const app = createIntegrationApp();

  it("returns RUNNING with database metadata", async () => {
    const res = await request(app).get("/health");
    assert.equal(res.status, 200);
    assert.equal(res.body.status, "RUNNING");
    assert.ok(res.body.dbTime);
    assert.ok(res.body.dbVersion);
  });
});
