import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  FORBIDDEN_ROUTES,
  PROTECTED_ROUTES,
  PUBLIC_BODY_ROUTES,
  ROUTE_MANIFEST,
  VALIDATION_BODY_ROUTES,
} from "./helpers/routeManifest.js";
import { PLACEHOLDER_UUID } from "./helpers/fixtures.js";
import { request, jsonHeaders } from "./helpers/http.js";
import {
  createAgencyForbiddenTestApp,
  createContractApp,
  createUnauthorizedTestApp,
} from "./helpers/testApp.js";

/**
 * Payloads that fail Zod validation without reaching services.
 * @param {import('./helpers/routeManifest.js').ROUTE_MANIFEST[number]} route
 */
function invalidBodyForRoute(route) {
  if (route.path.startsWith("/auth/register")) {
    return { email: "bad", password: "short", fullName: "", phoneNumber: "1" };
  }
  if (route.path.startsWith("/auth/login")) {
    return { email: "not-an-email", password: "" };
  }
  if (route.path.startsWith("/auth/refresh")) {
    return { refreshToken: "" };
  }
  if (route.path.includes("/roles")) {
    return { roleCode: "" };
  }
  if (route.path.includes("classify/service-case")) {
    return { priorityLevel: "not-valid" };
  }
  if (route.path.includes("classify/emergency") || route.path.includes("/promote/emergency")) {
    return { severityCode: "not-valid" };
  }
  if (route.path.includes("/intake-reports") && route.path.endsWith("/dismiss")) {
    return { disposition: "not-valid" };
  }
  if (route.path.includes("/escalate")) {
    return { severityCode: "critical" };
  }
  if (route.path.startsWith("/locations")) {
    return { latitude: "x", longitude: "y", source: "user_shared" };
  }
  if (route.path === "/intake/reports") {
    return { channelCode: "", categoryCode: "", summary: "" };
  }
  if (route.path.includes("/agency/units") && route.path.includes("/status")) {
    return { status_code: "not-valid" };
  }
  if (route.path.includes("/agency/units") && route.method === "POST") {
    return {
      unit_code: "",
      unit_name: "",
      unit_type_code: "",
      base_location: { latitude: "x", longitude: 1 },
    };
  }
  if (route.path.includes("/agency/dispatches")) {
    return { status_code: "not-valid" };
  }
  if (route.path.includes("/agency/incidents") && route.path.includes("response-logs")) {
    return { message: "" };
  }
  if (route.path.startsWith("/admin/agencies/onboard")) {
    return { user_public_uuid: "not-a-uuid" };
  }
  if (route.path.includes("/admin/agencies") && route.path.includes("/representatives")) {
    return { user_public_uuid: "not-a-uuid" };
  }
  if (route.path.startsWith("/admin/agencies") && route.method === "PATCH") {
    return { name: 12345 };
  }
  if (route.path.startsWith("/operations/incidents") && route.path.endsWith("/status")) {
    return { statusCode: "" };
  }
  if (route.path.includes("/operations/dispatches") && route.method === "PATCH") {
    return { statusCode: "not-valid" };
  }
  if (route.path.includes("/operations/service-cases") && route.path.endsWith("/status")) {
    return { statusCode: "" };
  }
  if (route.path.includes("/operations/service-cases") && route.path.endsWith("/assignments")) {
    return { assigneeUserPublicUuid: "not-a-uuid" };
  }
  if (route.path.includes("/operations/service-cases") && route.path.endsWith("/resolve")) {
    return { resolutionSummary: "" };
  }
  if (route.path.includes("/operations/service-cases") && route.path.endsWith("/messages")) {
    return { message: "" };
  }
  if (route.path.includes("/operations/incidents") && route.path.endsWith("/agencies")) {
    return { agencyPublicUuid: "not-a-uuid" };
  }
  if (route.path.includes("/operations/incidents") && route.path.endsWith("/dispatches")) {
    return { unitPublicUuid: "not-a-uuid" };
  }
  if (route.path.includes("/operations/incidents") && route.path.endsWith("/notes")) {
    return { note: "" };
  }
  if (route.path.includes("/operations/incidents") && route.path.endsWith("/intake-reports")) {
    return { intakeReportPublicUuid: "not-a-uuid" };
  }
  if (route.path === "/operations/incidents" || route.path.includes("/gateway/999")) {
    return { severityCode: "not-valid" };
  }
  if (route.path.includes("/intake/service-cases") && route.method === "POST") {
    return { message: "" };
  }
  if (route.path.includes("/intake/reports") && route.path.endsWith("/location")) {
    return { location: { latitude: "x", longitude: "y" } };
  }
  return { severityCode: "not-valid" };
}

describe("API route contract", () => {
  describe("401 without Authorization", () => {
    const app = createUnauthorizedTestApp();

    for (const route of PROTECTED_ROUTES) {
      it(`${route.method} ${route.path} returns 401`, async () => {
        const res = await request(app)[route.method.toLowerCase()](route.path).set(jsonHeaders());
        assert.equal(res.status, 401);
        assert.equal(res.body.error?.code, "AUTH_HEADER_INVALID");
      });
    }
  });

  describe("403 forbidden persona", () => {
    const opsApp = createContractApp("citizen");
    const adminApp = createContractApp("citizen");
    const agencyApp = createAgencyForbiddenTestApp();

    for (const route of FORBIDDEN_ROUTES) {
      it(`${route.method} ${route.path} returns 403 for ${route.denyPersona}`, async () => {
        const app = route.agencyRouter
          ? agencyApp
          : route.path.startsWith("/admin")
            ? adminApp
            : opsApp;
        const agent = request(app)[route.method.toLowerCase()](route.path).set(
          jsonHeaders("unused"),
        );
        if (route.method === "POST" || route.method === "PATCH") {
          agent.send({});
        }
        const res = await agent;
        assert.equal(res.status, 403);
        assert.equal(res.body.error?.code, "FORBIDDEN");
      });
    }
  });

  describe("422 validation on invalid body", () => {
    for (const route of [...PUBLIC_BODY_ROUTES, ...VALIDATION_BODY_ROUTES]) {
      it(`${route.method} ${route.path} returns 422 for invalid body`, async () => {
        const persona = route.public ? null : (route.validationPersona ?? "systemAdmin");
        const app = route.public ? createUnauthorizedTestApp() : createContractApp(persona);
        const agent = request(app)[route.method.toLowerCase()](route.path).set(jsonHeaders("mock"));
        const res = await agent.send(invalidBodyForRoute(route));
        assert.equal(res.status, 422, JSON.stringify(res.body));
        assert.equal(res.body.error?.code, "VALIDATION_ERROR");
        assert.ok(Array.isArray(res.body.error?.details));
      });
    }
  });

  describe("404 unknown route", () => {
    const app = createUnauthorizedTestApp();

    it("GET /nope returns ROUTE_NOT_FOUND", async () => {
      const res = await request(app).get("/nope").set(jsonHeaders());
      assert.equal(res.status, 404);
      assert.equal(res.body.error?.code, "ROUTE_NOT_FOUND");
    });
  });

  it("route manifest covers expected endpoint count", () => {
    assert.ok(ROUTE_MANIFEST.length >= 70, `expected at least 70 routes, got ${ROUTE_MANIFEST.length}`);
  });

  describe("operations unlink intake report route manifest and validation", () => {
    const U = PLACEHOLDER_UUID;
    const routePath = `/operations/incidents/${U}/intake-reports/${U}`;

    it("manifest contains DELETE unlink route with correct properties", () => {
      const route = ROUTE_MANIFEST.find((r) => r.method === "DELETE" && r.path === routePath);
      assert.ok(route, `expected route ${routePath} to be present in manifest`);
      assert.deepEqual(route.permissions, ["incident.update_status"]);
      assert.equal(route.denyPersona, "citizen");
      assert.equal(route.hasBodyValidator, true);
      assert.equal(route.validationPersona, "dispatcher");
    });

    const app = createContractApp("dispatcher");

    it("returns 422 when reason is missing", async () => {
      const res = await request(app).delete(routePath).set(jsonHeaders("mock")).send({});
      assert.equal(res.status, 422, JSON.stringify(res.body));
      assert.equal(res.body.error?.code, "VALIDATION_ERROR");
    });

    it("returns 422 when reason is blank", async () => {
      const res = await request(app).delete(routePath).set(jsonHeaders("mock")).send({ reason: "" });
      assert.equal(res.status, 422, JSON.stringify(res.body));
      assert.equal(res.body.error?.code, "VALIDATION_ERROR");
    });

    it("returns 422 when reason is too long", async () => {
      const long = "a".repeat(501);
      const res = await request(app).delete(routePath).set(jsonHeaders("mock")).send({ reason: long });
      assert.equal(res.status, 422, JSON.stringify(res.body));
      assert.equal(res.body.error?.code, "VALIDATION_ERROR");
    });

    it("returns 422 for invalid incidentPublicUuid param", async () => {
      const badPath = `/operations/incidents/not-a-uuid/intake-reports/${U}`;
      const res = await request(app).delete(badPath).set(jsonHeaders("mock")).send({ reason: "valid" });
      assert.equal(res.status, 422, JSON.stringify(res.body));
      assert.equal(res.body.error?.code, "VALIDATION_ERROR");
    });

    it("returns 422 for invalid reportPublicUuid param", async () => {
      const badPath = `/operations/incidents/${U}/intake-reports/not-a-uuid`;
      const res = await request(app).delete(badPath).set(jsonHeaders("mock")).send({ reason: "valid" });
      assert.equal(res.status, 422, JSON.stringify(res.body));
      assert.equal(res.body.error?.code, "VALIDATION_ERROR");
    });
  });
});
