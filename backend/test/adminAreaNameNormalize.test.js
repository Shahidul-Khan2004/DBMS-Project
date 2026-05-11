import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  adminAreaNameMatchesKeys,
  expandNormalizedNameKeys,
  normalizeAdministrativeAreaName,
} from "../src/domain/adminAreaNameNormalize.js";

describe("adminAreaNameNormalize", () => {
  it("lowercases trims collapses space and strips punctuation", () => {
    assert.equal(normalizeAdministrativeAreaName("  Dhaka, "), "dhaka");
    assert.equal(normalizeAdministrativeAreaName("Cox's Bazar"), "coxsbazar");
  });

  it("maps common spelling variants", () => {
    assert.equal(normalizeAdministrativeAreaName("Chittagong"), "chattogram");
    assert.equal(normalizeAdministrativeAreaName("Comilla"), "cumilla");
    assert.equal(normalizeAdministrativeAreaName("Jessore"), "jashore");
  });

  it("expandNormalizedNameKeys includes synonym variants", () => {
    const keys = expandNormalizedNameKeys("Chittagong");
    assert.ok(keys.includes("chattogram"));
  });

  it("adminAreaNameMatchesKeys compares against expanded keys", () => {
    const keys = expandNormalizedNameKeys("Comilla");
    assert.ok(adminAreaNameMatchesKeys("Cumilla", keys));
  });
});
