import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { integrationSkipMessage, isDbAvailable } from "../helpers/dbGate.js";

const dbUp = await isDbAvailable();
import { request, jsonHeaders } from "../helpers/http.js";
import { createIntegrationApp } from "../helpers/testApp.js";
import { getAdminToken } from "../helpers/authTokens.js";
import { PLACEHOLDER_UUID } from "../helpers/fixtures.js";

describe("users integration", { skip: !dbUp }, () => {
  it(integrationSkipMessage(), { skip: true });

  const app = createIntegrationApp();

  it("GET /users/me returns admin profile when logged in", async () => {
    const token = await getAdminToken(app);
    const res = await request(app).get("/users/me").set(jsonHeaders(token));
    assert.equal(res.status, 200);
    assert.ok(res.body.user?.email);
    assert.ok(res.body.authz?.permissions?.includes("agency.manage"));
    // secondary_phone_number must be present (null or string)
    assert.ok("secondary_phone_number" in res.body.user, "user must include secondary_phone_number");
  });

  it("POST /users/:userId/roles returns 403 without auth.manage_roles", async () => {
    const res = await request(app)
      .post(`/users/${PLACEHOLDER_UUID}/roles`)
      .set(jsonHeaders("invalid-token"));

    assert.equal(res.status, 401);
  });

  it("PATCH /users/me/profile returns 401 when unauthenticated", async () => {
    const res = await request(app)
      .patch("/users/me/profile")
      .set(jsonHeaders())
      .send({ fullName: "Oishi" });
    assert.equal(res.status, 401);
  });

  it("PATCH /users/me/profile updates fullName successfully", async () => {
    const token = await getAdminToken(app);
    const res = await request(app)
      .patch("/users/me/profile")
      .set(jsonHeaders(token))
      .send({ fullName: "Updated Admin Name" });
    assert.equal(res.status, 200);
    assert.equal(res.body.message, "Profile updated successfully");
    assert.equal(res.body.user.full_name, "Updated Admin Name");
    assert.ok("secondary_phone_number" in res.body.user);
  });

  it("PATCH /users/me/profile clears secondaryPhoneNumber with null", async () => {
    const token = await getAdminToken(app);
    // First set a secondary phone
    await request(app)
      .patch("/users/me/profile")
      .set(jsonHeaders(token))
      .send({ secondaryPhoneNumber: "01800000001" });

    // Then clear it
    const res = await request(app)
      .patch("/users/me/profile")
      .set(jsonHeaders(token))
      .send({ secondaryPhoneNumber: null });
    assert.equal(res.status, 200);
    assert.equal(res.body.user.secondary_phone_number, null);
  });

  it("PATCH /users/me/profile rejects secondary phone same as primary", async () => {
    const token = await getAdminToken(app);

    // First get current phone
    const meRes = await request(app).get("/users/me").set(jsonHeaders(token));
    const currentPhone = meRes.body.user.phone_number;

    const res = await request(app)
      .patch("/users/me/profile")
      .set(jsonHeaders(token))
      .send({ secondaryPhoneNumber: currentPhone });
    assert.equal(res.status, 422);
    assert.equal(res.body.error?.code, "DUPLICATE_PHONE");
  });

  it("PATCH /users/me/profile rejects phoneNumber change that matches existing secondary phone", async () => {
    const token = await getAdminToken(app);

    // Set a known secondary phone first
    await request(app)
      .patch("/users/me/profile")
      .set(jsonHeaders(token))
      .send({ secondaryPhoneNumber: "01800000000" });

    // Now change primary to the same value as secondary — must be rejected
    const res = await request(app)
      .patch("/users/me/profile")
      .set(jsonHeaders(token))
      .send({ phoneNumber: "01800000000" });
    assert.equal(res.status, 422);
    assert.equal(res.body.error?.code, "DUPLICATE_PHONE");

    // Verify DB was not mutated — secondary should still differ from primary
    const meRes = await request(app).get("/users/me").set(jsonHeaders(token));
    assert.notEqual(
      meRes.body.user.phone_number,
      meRes.body.user.secondary_phone_number,
      "primary and secondary phone must not be equal after rejected request",
    );
  });

  it("PATCH /users/me/profile rejects invalid phone length", async () => {
    const token = await getAdminToken(app);
    const res = await request(app)
      .patch("/users/me/profile")
      .set(jsonHeaders(token))
      .send({ phoneNumber: "0170000" });
    assert.equal(res.status, 422);
    assert.equal(res.body.error?.code, "VALIDATION_ERROR");
  });
});