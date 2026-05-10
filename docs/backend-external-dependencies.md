# Backend external dependencies

Third-party services and data sources the NIERS backend integrates with or ships as reference data.

## Barikoi reverse geocoding

**Purpose:** When a client creates a `locations` row (standalone `POST /locations`, inline `location` on intake, or structured `location` on standalone `POST /operations/incidents`) **without** `admin_area_id`, the server calls Barikoi reverse geocode to obtain division / district / sub-district (upazila) / union labels, then matches them to seeded `administrative_areas` rows.

**Configuration:** Set `BARIKOI_API_KEY` in the backend environment. If unset, resolution is skipped and `admin_area_id` remains `null` (submissions still succeed). If set, an **invalid key** or **usage/rate limit** from Barikoi is surfaced as **`503`** with `BARIKOI_API_KEY_REJECTED` or `BARIKOI_QUOTA_EXCEEDED` so operators can rotate the key (see `docs/backend-api.md` §6.1). Verify a key against production from the repo root: `npm run test:barikoi-live` (loads `backend/.env`, requires network).

**Implementation:** [`backend/src/integrations/barikoiReverseGeocoder.js`](../backend/src/integrations/barikoiReverseGeocoder.js) — HTTP GET to `https://barikoi.xyz/v2/api/search/reverse/geocode` with a ~2.5s timeout. Matching logic: [`backend/src/services/adminAreaFromGpsService.js`](../backend/src/services/adminAreaFromGpsService.js).

**References:**

- [Barikoi API documentation](https://docs.barikoi.com/api/)
- [Postman: Barikoi Location API](https://www.postman.com/rilus-barikoi/barikoi-location-api/collection/sozb8j6/location-api)

**Operational notes:** Quotas and billing are governed by your Barikoi account. Reverse geocoding runs **before** opening the main DB transaction so MySQL connections are not held during HTTP.

## Bangladesh administrative areas seed

**Purpose:** `administrative_areas` stores the hierarchy (`division` → `district` → `upazila` → `union`, …) used for foreign keys such as `locations.admin_area_id` and for GPS resolution above.

**Source:** Data is derived from the [nuhil/bangladesh-geocode](https://github.com/nuhil/bangladesh-geocode) project (MIT). Vendored notice: [`backend/third_party/bangladesh-geocode/README.md`](../backend/third_party/bangladesh-geocode/README.md).

**Committed artifact:** [`backend/src/schemas/docker-init/22_seed_administrative_areas.sql`](../backend/src/schemas/docker-init/22_seed_administrative_areas.sql) — applied on fresh Docker MySQL init with the rest of [`docker-init/`](../backend/src/schemas/docker-init/).

**Regeneration:** From the repository root, `npm run generate:admin-areas` runs [`backend/scripts/generate-admin-areas-seed.mjs`](../backend/scripts/generate-admin-areas-seed.mjs) (requires network to read upstream JSON). Maintainer workflow is described in [`backend/README.md`](../backend/README.md).

**Relationship to Barikoi:** Barikoi returns human-readable admin names; the seed uses canonical English spellings. The backend normalizes and applies a small synonym map (e.g. Chittagong/Chattogram, Comilla/Cumilla) before matching. Ambiguous or unknown strings result in `admin_area_id` left `null`.
