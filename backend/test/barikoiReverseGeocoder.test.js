import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  classifyBarikoiAuthOrQuotaFailure,
  normalizeBarikoiPlace,
  reverseGeocodeBarikoi,
  searchPlacesBarikoi,
} from "../src/integrations/barikoiReverseGeocoder.js";

describe("classifyBarikoiAuthOrQuotaFailure", () => {
  it("maps HTTP 401/403 to invalid_key", () => {
    assert.equal(classifyBarikoiAuthOrQuotaFailure(401, {})?.kind, "invalid_key");
    assert.equal(classifyBarikoiAuthOrQuotaFailure(403, { message: "bad" })?.kind, "invalid_key");
  });

  it("maps HTTP 429/402 to quota", () => {
    assert.equal(classifyBarikoiAuthOrQuotaFailure(429, {})?.kind, "quota");
    assert.equal(classifyBarikoiAuthOrQuotaFailure(402, {})?.kind, "quota");
  });

  it("maps JSON body status when HTTP is 200", () => {
    const r = classifyBarikoiAuthOrQuotaFailure(200, { status: 403, message: "Invalid key" });
    assert.equal(r?.kind, "invalid_key");
    assert.equal(r?.httpStatus, 200);
    assert.equal(r?.providerMessage, "Invalid key");
  });

  it("returns null for unrelated statuses", () => {
    assert.equal(classifyBarikoiAuthOrQuotaFailure(200, { status: 200, place: {} }), null);
    assert.equal(classifyBarikoiAuthOrQuotaFailure(404, {}), null);
    assert.equal(classifyBarikoiAuthOrQuotaFailure(null, {}), null);
  });
});

describe("barikoiReverseGeocoder", () => {
  it("parses Barikoi autocomplete search places with coordinates", async () => {
    const requestedUrls = [];
    const body = {
      status: 200,
      places: [
        {
          id: 635085,
          longitude: 90.369999116958,
          latitude: 23.83729875602,
          address: "Mirpur DOHS, Mirpur DOHS",
          city: "Dhaka",
          area: "Mirpur",
          uCode: "PFSU6037",
        },
      ],
    };

    const r = await searchPlacesBarikoi({
      query: "mirpur",
      apiKey: "test-key",
      fetchFn: async (url) => {
        requestedUrls.push(String(url));
        return {
          status: 200,
          json: async () => body,
        };
      },
    });

    assert.equal(r.places.length, 1);
    assert.equal(r.places[0].id, "PFSU6037");
    assert.equal(r.places[0].latitude, 23.83729875602);
    assert.equal(r.places[0].longitude, 90.369999116958);
    assert.equal(r.places[0].label, "Mirpur DOHS, Mirpur DOHS");
    assert.match(requestedUrls[0], /\/v2\/api\/search\/autocomplete\/place\?/);
    assert.match(requestedUrls[0], /country_code=bd/);
  });

  it("normalizeBarikoiPlace maps sub_district to upazila", () => {
    const p = normalizeBarikoiPlace({
      division: "Dhaka",
      district: "Dhaka",
      sub_district: "Dhanmondi",
      union: null,
      address: "x",
    });
    assert.equal(p.upazila, "Dhanmondi");
  });

  it("returns empty place when api key missing", async () => {
    const r = await reverseGeocodeBarikoi({
      latitude: 23.81,
      longitude: 90.41,
      apiKey: "",
      fetchFn: async () => {
        throw new Error("should not call");
      },
    });
    assert.equal(r.place.division, null);
    assert.equal(r.httpStatus, null);
    assert.equal(r.authOrQuotaFailure, null);
  });

  it("parses JSON on success", async () => {
    const body = {
      status: 200,
      place: {
        division: "Dhaka",
        district: "Dhaka",
        sub_district: "Tejgaon",
        union: null,
        address: "Test",
      },
    };
    const r = await reverseGeocodeBarikoi({
      latitude: 1,
      longitude: 2,
      apiKey: "test-key",
      baseUrl: "https://example.test/reverse",
      fetchFn: async () => ({
        status: 200,
        json: async () => body,
      }),
    });
    assert.equal(r.place.district, "Dhaka");
    assert.equal(r.place.upazila, "Tejgaon");
    assert.equal(r.httpStatus, 200);
    assert.equal(r.authOrQuotaFailure, null);
  });

  it("sets authOrQuotaFailure on HTTP 429", async () => {
    const r = await reverseGeocodeBarikoi({
      latitude: 1,
      longitude: 2,
      apiKey: "k",
      baseUrl: "https://example.test/reverse",
      fetchFn: async () => ({
        status: 429,
        json: async () => ({ message: "Too many requests" }),
      }),
    });
    assert.equal(r.authOrQuotaFailure?.kind, "quota");
    assert.equal(r.authOrQuotaFailure?.httpStatus, 429);
  });

  it("treats timeout as empty place", async () => {
    const r = await reverseGeocodeBarikoi({
      latitude: 1,
      longitude: 2,
      apiKey: "k",
      baseUrl: "https://example.test/reverse",
      timeoutMs: 1,
      fetchFn: () =>
        new Promise((_, reject) => {
          setTimeout(() => reject(new Error("aborted")), 50);
        }),
    });
    assert.equal(r.place.address, null);
    assert.equal(r.authOrQuotaFailure, null);
  });
});
