import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { isDbAvailable } from "../helpers/dbGate.js";
import { request, jsonHeaders } from "../helpers/http.js";
import { createIntegrationApp } from "../helpers/testApp.js";
import { registerTestUser } from "../helpers/registerTestUser.js";

const dbUp = await isDbAvailable();

describe("locations integration", { skip: !dbUp }, () => {

  const app = createIntegrationApp();

  it("GET /locations/my returns array for citizen", async () => {
    const { accessToken } = await registerTestUser(app);
    const res = await request(app).get("/locations/my").set(jsonHeaders(accessToken));
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.locations));
  });

  it("GET /locations/search returns 503 or 200 when Barikoi configured", async () => {
    const { accessToken } = await registerTestUser(app);
    const res = await request(app)
      .get("/locations/search")
      .query({ query: "Dhaka" })
      .set(jsonHeaders(accessToken));

    if (!process.env.BARIKOI_API_KEY) {
      assert.equal(res.status, 503);
      assert.equal(res.body.error?.code, "BARIKOI_API_KEY_MISSING");
      return;
    }
    assert.ok([200, 503].includes(res.status), JSON.stringify(res.body));
  });
});
