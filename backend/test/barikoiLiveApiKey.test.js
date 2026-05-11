/**
 * Verifies BARIKOI_API_KEY against the real Barikoi reverse geocode endpoint.
 *
 * Run from repo root (loads `backend/.env` via dotenv):
 *   npm run test:barikoi-live
 *
 * Requires network and `BARIKOI_API_KEY` in `backend/.env` (or the environment).
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { reverseGeocodeBarikoi } from "../src/integrations/barikoiReverseGeocoder.js";

const runLive =
  process.env.RUN_BARIKOI_LIVE === "1" && String(process.env.BARIKOI_API_KEY ?? "").trim().length > 0;

(runLive ? describe : describe.skip)("Barikoi live API key", () => {
  it("reverse geocode succeeds for Dhaka coordinates", async () => {
    // Production default is 3s; CI / slow links often exceed that and yield httpStatus null (timeout).
    const r = await reverseGeocodeBarikoi({
      latitude: 23.810331,
      longitude: 90.412521,
      timeoutMs: 5_000,
    });
    assert.equal(r.authOrQuotaFailure, null, "unexpected auth/quota failure");
    assert.equal(
      r.httpStatus,
      200,
      r.httpStatus == null
        ? "no HTTP response (timeout or network); try again or increase timeoutMs"
        : `unexpected HTTP status ${r.httpStatus}`,
    );
    const ok =
      Boolean(r.place.division) ||
      Boolean(r.place.district) ||
      Boolean(r.place.address);
    assert.ok(ok, "expected at least division, district, or address from Barikoi");
  });
});
