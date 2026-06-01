import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { isDbAvailable } from "../helpers/dbGate.js";
import { request, jsonHeaders } from "../helpers/http.js";
import { createIntegrationApp } from "../helpers/testApp.js";
import { registerTestUser } from "../helpers/registerTestUser.js";

const dbUp = await isDbAvailable();

describe("notifications integration", { skip: !dbUp }, () => {

  const app = createIntegrationApp();

  it("GET /notifications/my returns list", async () => {
    const { accessToken } = await registerTestUser(app);
    const res = await request(app).get("/notifications/my").set(jsonHeaders(accessToken));
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.notifications));
  });

  it("GET /notifications/my/unread-count returns count", async () => {
    const { accessToken } = await registerTestUser(app);
    const res = await request(app).get("/notifications/my/unread-count").set(jsonHeaders(accessToken));
    assert.equal(res.status, 200);
    assert.equal(typeof res.body.unreadCount, "number");
  });
});
