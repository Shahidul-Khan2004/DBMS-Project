import { createApp } from "../../src/createApp.js";
import { createTestAgencyContext, createTestAuth } from "./testAuth.js";

/**
 * @param {import('./testAuth.js').PERSONAS} personaKey
 */
export function createContractApp(personaKey) {
  const options = { requireAuth: createTestAuth(personaKey) };
  if (personaKey === "agencyRep") {
    options.requireAgencyContext = createTestAgencyContext("agencyRep");
  }
  return createApp(options);
}

/** Real auth middleware; no DB bootstrap or workers. */
export function createIntegrationApp() {
  return createApp();
}

/** Default app for 401 tests (real requireAuth). */
export function createUnauthorizedTestApp() {
  return createApp();
}

/**
 * App for agency-route 403 tests: citizen auth but agency context injected so permission check runs.
 */
export function createAgencyForbiddenTestApp() {
  return createApp({
    requireAuth: createTestAuth("citizen"),
    requireAgencyContext: createTestAgencyContext("agencyRep"),
  });
}
