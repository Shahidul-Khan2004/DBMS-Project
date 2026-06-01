import assert from "node:assert/strict";
import { describe, it } from "node:test";
import pool from "../../src/config/db.js";
import { ROLE_CODES } from "../../src/services/rbacService.js";
import { isDbAvailable } from "../helpers/dbGate.js";
import { SEED } from "../helpers/fixtures.js";
import { request, jsonHeaders } from "../helpers/http.js";
import { createIntegrationApp } from "../helpers/testApp.js";
import { getAdminToken } from "../helpers/authTokens.js";
import { registerTestUser } from "../helpers/registerTestUser.js";

const dbUp = await isDbAvailable();

describe("admin agency membership integration", { skip: !dbUp }, () => {

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

  it("deactivate revokes agency_representative; re-link restores access", async () => {
    const registered = await registerTestUser(app);
    const adminToken = await getAdminToken(app);

    const onboardRes = await request(app)
      .post("/admin/agencies/onboard")
      .set(jsonHeaders(adminToken))
      .send({
        user_public_uuid: registered.user.id,
        agency_public_uuid: SEED.fireAgencyPublicUuid,
      });

    assert.equal(onboardRes.status, 201, JSON.stringify(onboardRes.body));
    const membershipPublicUuid = onboardRes.body.membership_public_uuid;
    const userPublicUuid = onboardRes.body.user_public_uuid;

    const [users] = await pool.execute(`SELECT id FROM users WHERE email = ? LIMIT 1`, [
      registered.email,
    ]);
    const userId = users[0]?.id;
    assert.ok(userId);
    assert.ok(await hasAgencyRepRole(userId));

    const deactivateRes = await request(app)
      .patch(`/admin/agency-memberships/${membershipPublicUuid}/deactivate`)
      .set(jsonHeaders(adminToken));

    assert.equal(deactivateRes.status, 200);
    assert.equal(deactivateRes.body.membership?.membership_status, "inactive");
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

    const relinkRes = await request(app)
      .post(`/admin/agencies/${SEED.fireAgencyPublicUuid}/representatives`)
      .set(jsonHeaders(adminToken))
      .send({ user_public_uuid: userPublicUuid });

    assert.equal(relinkRes.status, 201);
    assert.equal(relinkRes.body.representative?.membership_status, "active");
    assert.ok(await hasAgencyRepRole(userId));

    const activeLoginRes = await request(app)
      .post("/auth/login")
      .set(jsonHeaders())
      .send({ email: registered.email, password: registered.password });

    assert.equal(activeLoginRes.status, 200);
    assert.ok(
      (activeLoginRes.body.authz?.roleCodes ?? []).includes(ROLE_CODES.AGENCY_REPRESENTATIVE),
    );

    const activeMeRes = await request(app)
      .get("/agency/me")
      .set(jsonHeaders(activeLoginRes.body.accessToken));

    assert.equal(activeMeRes.status, 200);
    assert.equal(activeMeRes.body.agency?.agency_code, "DHK-FIRE-01");
  });
});
