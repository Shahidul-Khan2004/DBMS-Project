import supertest from "supertest";

/**
 * @param {import("express").Express} app
 */
export function request(app) {
  return supertest(app);
}

/**
 * @param {string} [token]
 */
export function jsonHeaders(token) {
  const headers = { "Content-Type": "application/json" };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return headers;
}
