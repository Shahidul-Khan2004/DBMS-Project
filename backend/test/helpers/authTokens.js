import assert from "node:assert/strict";
import { request, jsonHeaders } from "./http.js";

const tokenCache = new Map();

/**
 * @param {import("express").Express} app
 * @param {string} email
 * @param {string} password
 */
export async function loginAs(app, email, password) {
  const cacheKey = `${email}:${password}`;
  if (tokenCache.has(cacheKey)) {
    return tokenCache.get(cacheKey);
  }

  const res = await request(app)
    .post("/auth/login")
    .set(jsonHeaders())
    .send({ email, password });

  assert.equal(
    res.status,
    200,
    `login failed for ${email}: ${res.status} ${JSON.stringify(res.body)}`,
  );
  assert.ok(res.body.accessToken, "expected accessToken in login response");

  tokenCache.set(cacheKey, res.body.accessToken);
  return res.body.accessToken;
}

export async function getAdminToken(app) {
  const email = process.env.SYSTEM_ADMIN__EMAIL;
  const password = process.env.SYSTEM_ADMIN_PASSWORD;
  if (!email || !password) {
    throw new Error("SYSTEM_ADMIN__EMAIL and SYSTEM_ADMIN_PASSWORD are required for admin integration tests");
  }
  return loginAs(app, email, password);
}

export async function getAgencyRepToken(app) {
  const password = process.env.DEMO_REP_PASSWORD;
  if (!password) {
    throw new Error("DEMO_REP_PASSWORD is required for agency rep integration tests");
  }
  return loginAs(app, "fire.rep@niers.test", password);
}

export async function getDispatcherToken(app) {
  const password = process.env.DEMO_DISPATCHER_PASSWORD;
  if (!password) {
    throw new Error("DEMO_DISPATCHER_PASSWORD is required for dispatcher integration tests");
  }
  return loginAs(app, "dispatcher@niers.test", password);
}

export function clearTokenCache() {
  tokenCache.clear();
}
