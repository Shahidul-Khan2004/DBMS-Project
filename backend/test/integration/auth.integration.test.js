import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { integrationSkipMessage, isDbAvailable } from "../helpers/dbGate.js";
import { request, jsonHeaders } from "../helpers/http.js";
import { createIntegrationApp } from "../helpers/testApp.js";
import { registerTestUser } from "../helpers/registerTestUser.js";

const dbUp = await isDbAvailable();

describe("auth integration", { skip: !dbUp }, () => {
  it(integrationSkipMessage(), { skip: true });

  const app = createIntegrationApp();

  it("POST /auth/register creates user and returns tokens", async () => {
    const { accessToken, user } = await registerTestUser(app);
    assert.ok(accessToken);
    assert.ok(user?.id);
  });

  it("POST /auth/login rejects invalid credentials", async () => {
    const res = await request(app)
      .post("/auth/login")
      .set(jsonHeaders())
      .send({ email: "nobody@niers.test", password: "wrong-password" });

    assert.equal(res.status, 401);
    assert.equal(res.body.error?.code, "INVALID_CREDENTIALS");
  });

  it("GET /users/me returns profile for registered user", async () => {
    const { email, accessToken } = await registerTestUser(app, { fullName: "Me Test User" });

    const res = await request(app).get("/users/me").set(jsonHeaders(accessToken));

    assert.equal(res.status, 200);
    assert.equal(res.body.user?.email, email);
    assert.ok(Array.isArray(res.body.authz?.roleCodes));
  });
});
