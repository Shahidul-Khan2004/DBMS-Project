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

  it("GET /locations/my returns 422 when sort=distance_asc without nearLocationId", async () => {
    const { accessToken } = await registerTestUser(app);
    const res = await request(app)
      .get("/locations/my")
      .query({ sort: "distance_asc" })
      .set(jsonHeaders(accessToken));
    assert.equal(res.status, 422);
    assert.equal(res.body.error?.code, "VALIDATION_ERROR");
  });

  it("GET /locations/my supports distance sort with includeDistance", async () => {
    const { accessToken } = await registerTestUser(app);

    const createA = await request(app)
      .post("/locations")
      .set(jsonHeaders(accessToken))
      .send({
        latitude: 23.78,
        longitude: 90.4,
        source: "user_shared",
      });
    assert.equal(createA.status, 201);

    const createB = await request(app)
      .post("/locations")
      .set(jsonHeaders(accessToken))
      .send({
        latitude: 23.79,
        longitude: 90.41,
        source: "user_shared",
      });
    assert.equal(createB.status, 201);

    const refId = createA.body.location.id;
    const res = await request(app)
      .get("/locations/my")
      .query({
        sort: "distance_asc",
        nearLocationId: String(refId),
        includeDistance: "true",
      })
      .set(jsonHeaders(accessToken));

    assert.equal(res.status, 200);
    assert.ok(res.body.locations.length >= 2);
    assert.ok("distance_km" in res.body.locations[0]);
    const withDistance = res.body.locations.filter((l) => l.distance_km != null);
    assert.ok(withDistance.length >= 2);
    assert.ok(withDistance[0].distance_km <= withDistance[1].distance_km);
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
