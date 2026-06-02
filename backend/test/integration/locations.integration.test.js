import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { isDbAvailable } from "../helpers/dbGate.js";
import { request, jsonHeaders } from "../helpers/http.js";
import { createIntegrationApp } from "../helpers/testApp.js";
import { registerTestUser } from "../helpers/registerTestUser.js";

const dbUp = await isDbAvailable();

/** Minimal valid location body for POST /locations */
const TEST_LOCATION_BODY = {
  latitude: 23.8103,
  longitude: 90.4125,
  address_text: "Dhaka, Bangladesh",
  source: "user_shared",
};

describe("locations integration", { skip: !dbUp }, () => {

  const app = createIntegrationApp();

  // ─── existing smoke tests ────────────────────────────────────────────────

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

  // ─── saved locations feature tests ──────────────────────────────────────

  it("POST /locations creates a location but does not appear in GET /locations/my until saved", async () => {
    const { accessToken } = await registerTestUser(app);

    const createRes = await request(app)
      .post("/locations")
      .set(jsonHeaders(accessToken))
      .send(TEST_LOCATION_BODY);
    assert.equal(createRes.status, 201, JSON.stringify(createRes.body));
    assert.ok(createRes.body.location?.publicUuid, "expected publicUuid in created location");

    const myRes = await request(app).get("/locations/my").set(jsonHeaders(accessToken));
    assert.equal(myRes.status, 200);
    const found = myRes.body.locations.some(
      (l) => l.publicUuid === createRes.body.location.publicUuid,
    );
    assert.equal(found, false, "newly created location should not appear in /my until saved");
  });

  it("POST /locations/:publicUuid/save saves the location", async () => {
    const { accessToken } = await registerTestUser(app);

    const createRes = await request(app)
      .post("/locations")
      .set(jsonHeaders(accessToken))
      .send(TEST_LOCATION_BODY);
    assert.equal(createRes.status, 201, JSON.stringify(createRes.body));
    const { publicUuid } = createRes.body.location;

    const saveRes = await request(app)
      .post(`/locations/${publicUuid}/save`)
      .set(jsonHeaders(accessToken));
    assert.equal(saveRes.status, 200, JSON.stringify(saveRes.body));
    assert.ok(saveRes.body.savedLocationPublicUuid, "expected savedLocationPublicUuid");
  });

  it("GET /locations/my returns the saved location", async () => {
    const { accessToken } = await registerTestUser(app);

    const createRes = await request(app)
      .post("/locations")
      .set(jsonHeaders(accessToken))
      .send(TEST_LOCATION_BODY);
    const { publicUuid } = createRes.body.location;

    await request(app).post(`/locations/${publicUuid}/save`).set(jsonHeaders(accessToken));

    const myRes = await request(app).get("/locations/my").set(jsonHeaders(accessToken));
    assert.equal(myRes.status, 200);
    const found = myRes.body.locations.find((l) => l.publicUuid === publicUuid);
    assert.ok(found, "saved location should appear in /my");
    assert.ok(found.savedLocationPublicUuid, "saved entry should include savedLocationPublicUuid");
  });

  it("saving the same location twice does not create duplicate active saved rows", async () => {
    const { accessToken } = await registerTestUser(app);

    const createRes = await request(app)
      .post("/locations")
      .set(jsonHeaders(accessToken))
      .send(TEST_LOCATION_BODY);
    const { publicUuid } = createRes.body.location;

    const first = await request(app)
      .post(`/locations/${publicUuid}/save`)
      .set(jsonHeaders(accessToken));
    assert.equal(first.status, 200, JSON.stringify(first.body));

    const second = await request(app)
      .post(`/locations/${publicUuid}/save`)
      .set(jsonHeaders(accessToken));
    assert.equal(second.status, 200, JSON.stringify(second.body));

    // UUIDs of the saved relationship should be the same (idempotent)
    assert.equal(
      first.body.savedLocationPublicUuid,
      second.body.savedLocationPublicUuid,
      "duplicate save should return the same savedLocationPublicUuid",
    );

    const myRes = await request(app).get("/locations/my").set(jsonHeaders(accessToken));
    const entries = myRes.body.locations.filter((l) => l.publicUuid === publicUuid);
    assert.equal(entries.length, 1, "should only have one active saved entry");
  });

  it("DELETE /locations/:publicUuid/save removes location from GET /locations/my", async () => {
    const { accessToken } = await registerTestUser(app);

    const createRes = await request(app)
      .post("/locations")
      .set(jsonHeaders(accessToken))
      .send(TEST_LOCATION_BODY);
    const { publicUuid } = createRes.body.location;

    await request(app).post(`/locations/${publicUuid}/save`).set(jsonHeaders(accessToken));

    const delRes = await request(app)
      .delete(`/locations/${publicUuid}/save`)
      .set(jsonHeaders(accessToken));
    assert.equal(delRes.status, 200, JSON.stringify(delRes.body));

    const myRes = await request(app).get("/locations/my").set(jsonHeaders(accessToken));
    const found = myRes.body.locations.some((l) => l.publicUuid === publicUuid);
    assert.equal(found, false, "unsaved location should no longer appear in /my");
  });

  it("DELETE /locations/:publicUuid/save does not delete the original location row", async () => {
    const { accessToken } = await registerTestUser(app);

    const createRes = await request(app)
      .post("/locations")
      .set(jsonHeaders(accessToken))
      .send(TEST_LOCATION_BODY);
    const { publicUuid } = createRes.body.location;

    await request(app).post(`/locations/${publicUuid}/save`).set(jsonHeaders(accessToken));
    await request(app).delete(`/locations/${publicUuid}/save`).set(jsonHeaders(accessToken));

    // The underlying location record should still be fetchable
    const getRes = await request(app)
      .get(`/locations/${publicUuid}`)
      .set(jsonHeaders(accessToken));
    assert.equal(getRes.status, 200, "location row must still exist after unsave");
    assert.equal(getRes.body.location?.publicUuid, publicUuid);
  });

  it("saving again after delete restores the location in GET /locations/my", async () => {
    const { accessToken } = await registerTestUser(app);

    const createRes = await request(app)
      .post("/locations")
      .set(jsonHeaders(accessToken))
      .send(TEST_LOCATION_BODY);
    const { publicUuid } = createRes.body.location;

    await request(app).post(`/locations/${publicUuid}/save`).set(jsonHeaders(accessToken));
    await request(app).delete(`/locations/${publicUuid}/save`).set(jsonHeaders(accessToken));

    const resaveRes = await request(app)
      .post(`/locations/${publicUuid}/save`)
      .set(jsonHeaders(accessToken));
    assert.equal(resaveRes.status, 200, JSON.stringify(resaveRes.body));
    assert.ok(resaveRes.body.savedLocationPublicUuid);

    const myRes = await request(app).get("/locations/my").set(jsonHeaders(accessToken));
    const found = myRes.body.locations.some((l) => l.publicUuid === publicUuid);
    assert.equal(found, true, "re-saved location should reappear in /my");
  });

  it("User A cannot see User B's saved locations in GET /locations/my", async () => {
    const userA = await registerTestUser(app);
    const userB = await registerTestUser(app);

    // userA creates and saves a location
    const createRes = await request(app)
      .post("/locations")
      .set(jsonHeaders(userA.accessToken))
      .send(TEST_LOCATION_BODY);
    const { publicUuid } = createRes.body.location;
    await request(app).post(`/locations/${publicUuid}/save`).set(jsonHeaders(userA.accessToken));

    // userB's /my should not include userA's saved location
    const myRes = await request(app).get("/locations/my").set(jsonHeaders(userB.accessToken));
    assert.equal(myRes.status, 200);
    const found = myRes.body.locations.some((l) => l.publicUuid === publicUuid);
    assert.equal(found, false, "User B should not see User A's saved locations");
  });

  it("User A cannot delete User B's saved relationship", async () => {
    const userA = await registerTestUser(app);
    const userB = await registerTestUser(app);

    // userA creates and saves a location
    const createRes = await request(app)
      .post("/locations")
      .set(jsonHeaders(userA.accessToken))
      .send(TEST_LOCATION_BODY);
    const { publicUuid } = createRes.body.location;
    await request(app).post(`/locations/${publicUuid}/save`).set(jsonHeaders(userA.accessToken));

    // userB tries to delete userA's saved relationship for the same location
    const delRes = await request(app)
      .delete(`/locations/${publicUuid}/save`)
      .set(jsonHeaders(userB.accessToken));
    // userB has no saved row for this location, so expect 404
    assert.equal(delRes.status, 404, JSON.stringify(delRes.body));
    assert.equal(delRes.body.error?.code, "SAVED_LOCATION_NOT_FOUND");

    // userA's saved entry should still be intact
    const myRes = await request(app).get("/locations/my").set(jsonHeaders(userA.accessToken));
    const found = myRes.body.locations.some((l) => l.publicUuid === publicUuid);
    assert.equal(found, true, "User A's saved location should be untouched");
  });

  it("saving a nonexistent location returns 404 LOCATION_NOT_FOUND", async () => {
    const { accessToken } = await registerTestUser(app);
    const fakeUuid = "00000000-0000-4000-8000-000000000099";

    const res = await request(app)
      .post(`/locations/${fakeUuid}/save`)
      .set(jsonHeaders(accessToken));
    assert.equal(res.status, 404, JSON.stringify(res.body));
    assert.equal(res.body.error?.code, "LOCATION_NOT_FOUND");
  });

  it("deleting save for a nonexistent location returns 404 LOCATION_NOT_FOUND", async () => {
    const { accessToken } = await registerTestUser(app);
    const fakeUuid = "00000000-0000-4000-8000-000000000099";

    const res = await request(app)
      .delete(`/locations/${fakeUuid}/save`)
      .set(jsonHeaders(accessToken));
    assert.equal(res.status, 404, JSON.stringify(res.body));
    assert.equal(res.body.error?.code, "LOCATION_NOT_FOUND");
  });

  it("deleting a location that exists but is not saved returns 404 SAVED_LOCATION_NOT_FOUND", async () => {
    const { accessToken } = await registerTestUser(app);

    // Create a location but do NOT save it
    const createRes = await request(app)
      .post("/locations")
      .set(jsonHeaders(accessToken))
      .send(TEST_LOCATION_BODY);
    const { publicUuid } = createRes.body.location;

    const delRes = await request(app)
      .delete(`/locations/${publicUuid}/save`)
      .set(jsonHeaders(accessToken));
    assert.equal(delRes.status, 404, JSON.stringify(delRes.body));
    assert.equal(delRes.body.error?.code, "SAVED_LOCATION_NOT_FOUND");
  });

  it("deleting a saved location does not affect intake reports referencing that location", async () => {
    const { accessToken } = await registerTestUser(app);

    // Create a location and save it
    const createRes = await request(app)
      .post("/locations")
      .set(jsonHeaders(accessToken))
      .send(TEST_LOCATION_BODY);
    assert.equal(createRes.status, 201, JSON.stringify(createRes.body));
    const { publicUuid } = createRes.body.location;
    await request(app).post(`/locations/${publicUuid}/save`).set(jsonHeaders(accessToken));

    // Create an intake report referencing the location by its publicUuid
    const intakeRes = await request(app)
      .post("/intake/reports")
      .set(jsonHeaders(accessToken))
      .send({
        channelCode: "web_portal",
        categoryCode: "medical",
        summary: "Test: location-history preservation",
        locationId: publicUuid,
      });
    assert.equal(intakeRes.status, 201, JSON.stringify(intakeRes.body));
    const reportPublicUuid = intakeRes.body.intake?.public_uuid;
    assert.ok(reportPublicUuid, "intake report should have a public_uuid");

    // Delete the saved location
    const delRes = await request(app)
      .delete(`/locations/${publicUuid}/save`)
      .set(jsonHeaders(accessToken));
    assert.equal(delRes.status, 200, JSON.stringify(delRes.body));

    // The intake report should still be fetchable and still reference the location
    const reportRes = await request(app)
      .get(`/intake/reports/${reportPublicUuid}`)
      .set(jsonHeaders(accessToken));
    assert.equal(reportRes.status, 200, JSON.stringify(reportRes.body));

    // And the underlying location row is unaffected
    const locRes = await request(app)
      .get(`/locations/${publicUuid}`)
      .set(jsonHeaders(accessToken));
    assert.equal(locRes.status, 200, "location must still exist after unsave");
    assert.equal(locRes.body.location?.publicUuid, publicUuid);
  });
});