import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildOnboardAgencyPayload,
  getSelectedLocationCoordinates,
} from "./build-onboard-agency-payload.ts";

describe("buildOnboardAgencyPayload", () => {
  it("builds minimal agency-only payload", () => {
    const payload = buildOnboardAgencyPayload({
      agencyCode: " DHK-01 ",
      agencyName: " Test Agency ",
      agencyTypeCode: "fire_service",
    });

    assert.deepEqual(payload, {
      agency: {
        agency_code: "DHK-01",
        name: "Test Agency",
        agency_type_code: "fire_service",
      },
    });
    assert.equal("user_public_uuid" in payload, false);
    assert.equal("head_office_location" in payload.agency, false);
  });

  it("omits empty optional strings", () => {
    const payload = buildOnboardAgencyPayload({
      agencyCode: "A1",
      agencyName: "Agency",
      agencyTypeCode: "police",
      description: "   ",
      addressText: "",
      placeName: "  ",
    });

    assert.equal(payload.agency.description, undefined);
    assert.equal(payload.agency.head_office_location, undefined);
  });

  it("includes description when trimmed non-empty", () => {
    const payload = buildOnboardAgencyPayload({
      agencyCode: "A1",
      agencyName: "Agency",
      agencyTypeCode: "police",
      description: "  North zone  ",
    });

    assert.equal(payload.agency.description, "North zone");
  });

  it("includes head_office_location from latitude/longitude", () => {
    const payload = buildOnboardAgencyPayload({
      agencyCode: "A1",
      agencyName: "Agency",
      agencyTypeCode: "fire_service",
      selectedLocation: { latitude: 23.81, longitude: 90.41 },
      addressText: "Dhaka",
      placeName: "HQ",
    });

    assert.deepEqual(payload.agency.head_office_location, {
      latitude: 23.81,
      longitude: 90.41,
      source: "manual_entry",
      address_text: "Dhaka",
      place_name: "HQ",
    });
  });

  it("extracts coordinates from lat/lng", () => {
    const coords = getSelectedLocationCoordinates({ lat: 23.5, lng: 90.2 });
    assert.deepEqual(coords, { latitude: 23.5, longitude: 90.2 });
  });

  it("extracts coordinates from latlng", () => {
    const coords = getSelectedLocationCoordinates({
      latlng: { lat: 23.5, lng: 90.2 },
    });
    assert.deepEqual(coords, { latitude: 23.5, longitude: 90.2 });
  });

  it("omits head_office_location when coordinates invalid", () => {
    const payload = buildOnboardAgencyPayload({
      agencyCode: "A1",
      agencyName: "Agency",
      agencyTypeCode: "fire_service",
      selectedLocation: { latitude: "bad", longitude: 90 },
      addressText: "Some address",
    });

    assert.equal(payload.agency.head_office_location, undefined);
  });

  it("never includes forbidden UI or camelCase keys", () => {
    const payload = buildOnboardAgencyPayload({
      agencyCode: "A1",
      agencyName: "Agency",
      agencyTypeCode: "fire_service",
    });

    const json = JSON.stringify(payload);
    const forbidden = [
      "agencyCode",
      "agencyName",
      "agencyType",
      "headOfficeLocation",
      "linkRepresentativeAfterCreate",
      "user_public_uuid",
      "representativeUserPublicUuid",
    ];

    for (const key of forbidden) {
      assert.equal(json.includes(`"${key}"`), false, `must not include ${key}`);
    }
  });
});
