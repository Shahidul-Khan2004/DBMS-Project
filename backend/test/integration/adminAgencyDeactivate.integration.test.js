import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { describe, it } from "node:test";
import pool from "../../src/config/db.js";
import { ROLE_CODES } from "../../src/services/rbacService.js";
import { integrationSkipMessage, isDbAvailable } from "../helpers/dbGate.js";
import { request, jsonHeaders } from "../helpers/http.js";
import { createIntegrationApp } from "../helpers/testApp.js";
import { getAdminToken } from "../helpers/authTokens.js";
import { registerTestUser } from "../helpers/registerTestUser.js";

const dbUp = await isDbAvailable();

describe("admin agency deactivate integration", { skip: !dbUp }, () => {
  it(integrationSkipMessage(), { skip: true });

  const app = createIntegrationApp();

  async function hasAgencyRepRole(userId) {
    const [rows] = await pool.execute(
      `
        SELECT 1
        FROM user_roles ur
        INNER JOIN roles r ON r.id = ur.role_id
        WHERE ur.user_id = ? AND r.role_code = ?
        LIMIT 1
      `,
      [userId, ROLE_CODES.AGENCY_REPRESENTATIVE],
    );
    return Boolean(rows[0]);
  }

  it("deactivate agency cascades representative memberships and revokes role", async () => {
    const registered = await registerTestUser(app);
    const adminToken = await getAdminToken(app);
    const agencyCode = `TEST-DEACT-${randomUUID().slice(0, 8)}`;

    const onboardRes = await request(app)
      .post("/admin/agencies/onboard")
      .set(jsonHeaders(adminToken))
      .send({
        user_public_uuid: registered.user.id,
        agency: {
          agency_code: agencyCode,
          name: "Test Deactivate Agency",
          agency_type_code: "fire_service",
          description: "Integration test agency for deactivate cascade",
        },
      });

    assert.equal(onboardRes.status, 201, JSON.stringify(onboardRes.body));
    const agencyPublicUuid = onboardRes.body.agency?.public_uuid;
    assert.ok(agencyPublicUuid);

    const [users] = await pool.execute(`SELECT id FROM users WHERE email = ? LIMIT 1`, [
      registered.email,
    ]);
    const userId = users[0]?.id;
    assert.ok(userId);
    assert.ok(await hasAgencyRepRole(userId));

    const loginBeforeRes = await request(app)
      .post("/auth/login")
      .set(jsonHeaders())
      .send({ email: registered.email, password: registered.password });

    assert.equal(loginBeforeRes.status, 200);
    const meBeforeRes = await request(app)
      .get("/agency/me")
      .set(jsonHeaders(loginBeforeRes.body.accessToken));
    assert.equal(meBeforeRes.status, 200);

    const deactivateRes = await request(app)
      .patch(`/admin/agencies/${agencyPublicUuid}/deactivate`)
      .set(jsonHeaders(adminToken));

    assert.equal(deactivateRes.status, 200, JSON.stringify(deactivateRes.body));
    assert.equal(deactivateRes.body.agency?.is_active, false);
    const reps = deactivateRes.body.representatives ?? [];
    assert.ok(reps.length >= 1);
    assert.ok(
      reps.every((r) => r.membership_status === "inactive"),
      "all representatives should be inactive after agency deactivate",
    );

    const [memberships] = await pool.execute(
      `
        SELECT am.membership_status, am.left_at
        FROM agency_memberships am
        INNER JOIN agencies a ON a.id = am.agency_id
        INNER JOIN users u ON u.id = am.user_id
        WHERE a.public_uuid = ?
          AND u.id = ?
          AND am.membership_role = 'representative'
        LIMIT 1
      `,
      [agencyPublicUuid, userId],
    );
    assert.equal(memberships[0]?.membership_status, "inactive");
    assert.ok(memberships[0]?.left_at);

    assert.equal(await hasAgencyRepRole(userId), false);

    const loginRes = await request(app)
      .post("/auth/login")
      .set(jsonHeaders())
      .send({ email: registered.email, password: registered.password });

    assert.equal(loginRes.status, 200);
    assert.ok(
      !(loginRes.body.authz?.roleCodes ?? []).includes(ROLE_CODES.AGENCY_REPRESENTATIVE),
      "deactivated rep should not have agency_representative in authz",
    );

    const inactiveMeRes = await request(app)
      .get("/agency/me")
      .set(jsonHeaders(loginRes.body.accessToken));

    assert.equal(inactiveMeRes.status, 403);
    assert.equal(inactiveMeRes.body.error?.code, "MEMBERSHIP_INACTIVE");

    const activateRes = await request(app)
      .patch(`/admin/agencies/${agencyPublicUuid}/activate`)
      .set(jsonHeaders(adminToken));

    assert.equal(activateRes.status, 200, JSON.stringify(activateRes.body));
    assert.equal(activateRes.body.agency?.is_active, true);
    assert.ok(
      (activateRes.body.representatives ?? []).every((r) => r.membership_status === "active"),
      "all representatives should be active after agency activate",
    );

    assert.ok(await hasAgencyRepRole(userId));

    const loginAfterRes = await request(app)
      .post("/auth/login")
      .set(jsonHeaders())
      .send({ email: registered.email, password: registered.password });

    assert.equal(loginAfterRes.status, 200);
    assert.ok(
      (loginAfterRes.body.authz?.roleCodes ?? []).includes(ROLE_CODES.AGENCY_REPRESENTATIVE),
    );

    const activeMeRes = await request(app)
      .get("/agency/me")
      .set(jsonHeaders(loginAfterRes.body.accessToken));

    assert.equal(activeMeRes.status, 200);
    assert.equal(activeMeRes.body.agency?.agency_code, agencyCode);
  });
});
