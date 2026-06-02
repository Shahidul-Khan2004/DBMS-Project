import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { isDbAvailable } from "../helpers/dbGate.js";
import { request, jsonHeaders } from "../helpers/http.js";
import { createIntegrationApp } from "../helpers/testApp.js";
import { registerTestUser } from "../helpers/registerTestUser.js";

const dbUp = await isDbAvailable();

describe("intake integration", { skip: !dbUp }, () => {

  const app = createIntegrationApp();

  it("GET /intake/reports/my returns array", async () => {
    const { accessToken } = await registerTestUser(app);
    const res = await request(app).get("/intake/reports/my").set(jsonHeaders(accessToken));
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.reports));
  });

  it("POST /intake/reports creates report with coordinates", async () => {
    const { accessToken } = await registerTestUser(app);
    const res = await request(app)
      .post("/intake/reports")
      .set(jsonHeaders(accessToken))
      .send({
        channelCode: "web_portal",
        categoryCode: "medical",
        summary: "Integration smoke report",
        location: {
          latitude: 23.8103,
          longitude: 90.4125,
          source: "user_shared",
        },
      });

    assert.equal(res.status, 201, JSON.stringify(res.body));
    assert.ok(res.body.intake?.public_uuid ?? res.body.intake);
  });
});
