import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { request, jsonHeaders } from "./http.js";

/** @returns {string} 11-digit Bangladesh-style mobile number */
export function randomBdPhone() {
  const n = Math.floor(Math.random() * 1e8);
  return `017${String(n).padStart(8, "0")}`.slice(0, 11);
}

/**
 * @param {import("express").Express} app
 * @param {object} [overrides]
 * @param {string} [overrides.email]
 * @param {string} [overrides.password]
 * @param {string} [overrides.fullName]
 * @param {string} [overrides.phoneNumber]
 */
export async function registerTestUser(app, overrides = {}) {
  const email = overrides.email ?? `test.${randomUUID()}@niers.test`;
  const password = overrides.password ?? "TestPass123!";

  const res = await request(app)
    .post("/auth/register")
    .set(jsonHeaders())
    .send({
      email,
      password,
      rePassword: password,
      fullName: overrides.fullName ?? "Integration Test User",
      phoneNumber: overrides.phoneNumber ?? randomBdPhone(),
    });

  assert.equal(res.status, 201, `register failed: ${JSON.stringify(res.body)}`);

  return {
    email,
    password,
    accessToken: res.body.accessToken,
    refreshToken: res.body.refreshToken,
    user: res.body.user,
  };
}
