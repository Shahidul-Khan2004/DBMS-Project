import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { isDbAvailable } from "../helpers/dbGate.js";

const dbUp = await isDbAvailable();
import { request, jsonHeaders } from "../helpers/http.js";
import { createIntegrationApp } from "../helpers/testApp.js";
import { getAdminToken } from "../helpers/authTokens.js";
import { PLACEHOLDER_UUID } from "../helpers/fixtures.js";

describe("users integration", { skip: !dbUp }, () => {

  const app = createIntegrationApp();

  it("GET /users/me returns admin profile when logged in", async () => {
    const token = await getAdminToken(app);
    const res = await request(app).get("/users/me").set(jsonHeaders(token));
    assert.equal(res.status, 200);
    assert.ok(res.body.user?.email);
    assert.ok(res.body.authz?.permissions?.includes("agency.manage"));
  });

  it("POST /users/:userId/roles returns 403 without auth.manage_roles", async () => {
    const res = await request(app)
      .post(`/users/${PLACEHOLDER_UUID}/roles`)
      .set(jsonHeaders("invalid-token"));

    assert.equal(res.status, 401);
  });
});
