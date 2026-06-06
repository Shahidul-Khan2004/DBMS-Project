# Backend API (Insomnia test guide)

Living reference for HTTP endpoints. Update this file whenever routes or contract-relevant validation change.

**Automated checks:** run `npm test` for fast route contract tests (401/403/422); run `npm run test:integration` for MySQL-backed HTTP smoke tests. See [backend/README.md](../backend/README.md#testing).

## Base URL

- Local: `http://localhost:8080`

## Headers

**Public (e.g. `/auth/*`, `/health`):**

```http
Content-Type: application/json
```

**Protected (everything else in this doc):**

```http
Content-Type: application/json
Authorization: Bearer <ACCESS_TOKEN>
```

## Standard error shape

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable message",
    "details": []
  }
}
```

`details` is optional; validation failures often populate it.

## User object (`user` in auth and `/users/me`)

- **`account_status`** — from `users.account_status` (`active` \| `suspended` \| `disabled` \| `pending_verification`); lifecycle source of truth.
- **`is_active`** — not a DB column; always `account_status === "active"` for clients that want a boolean.
- **`full_name`** and **`phone_number`** — from `user_profiles` (joined in the repository), not from `users`.

## Example: auth token response (`register`, `login`, `refresh`)

`user.id` is the user’s **public UUID** (not the internal DB id). `authz` is included on register, login, and refresh.

```json
{
  "message": "Login successful",
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "email": "john@example.com",
    "full_name": "John Doe",
    "phone_number": "01700000000",
    "account_status": "active",
    "is_active": true,
    "created_at": "2026-05-04T10:00:00.000Z",
    "updated_at": "2026-05-04T10:00:00.000Z"
  },
  "authz": {
    "roleCodes": ["citizen"],
    "permissions": []
  }
}
```

Register uses `"message": "User registered successfully"` (201). Refresh uses `"message": "Token refreshed successfully"` (200).

## Location payloads (intake, locations, operations)

Structured `location` objects use **`latitude`** and **`longitude`** (required numbers in validation).

- **`address_text`** — optional in the API schema. If omitted (preferred) or blank, the backend will derive and store a proper fallback from coordinates (see `locationAddressService`).
- **`place_name`** — optional.
- **`admin_area_id`** — optional positive integer; will be resolved from GPS when omitted (preferred).
- **`source`** — `user_shared` \| `dispatcher_selected` \| `api_geocoded` \| `manual_entry` (required on **`POST /locations`**; optional on intake / incident payloads where the schema allows it).

Do not send **`location`** and **`locationId`** in the same request.

## Distance sorting (list endpoints)

Optional proximity sorting uses **stored** `locations` rows only (no raw `latitude`/`longitude` query params).

| Query | Meaning |
| --- | --- |
| `sort=distance_asc` | Order by increasing distance from the reference point |
| `includeDistance=true` | Include `distance_km` on each row (only valid with `sort=distance_asc`) |
| `nearIncidentPublicUuid` | Reference = incident `current_location_id` |
| `nearIntakeReportPublicUuid` | Reference = intake `reported_location_id` |
| `nearServiceCasePublicUuid` | Reference = case `current_location_id`, else linked intake location |
| `nearFacilityPublicUuid` | Reference = facility `location_id` |
| `nearDisasterAffectedAreaPublicUuid` | Reference = geographic anchor for that upazila on the disaster (shelters/hubs/linked incidents in area); `422` `GEO_REFERENCE_UNAVAILABLE` if none |
| `nearLocationId` | Citizen only: numeric `id` from **`GET /locations/my`** (must be owned by caller) |

**Rules:**

- Exactly **one** `near*` parameter is required when `sort=distance_asc` (except **`GET /operations/units/available`**, which uses the required `incidentPublicUuid` as the reference).
- Any `near*` without `sort=distance_asc` → `422` `VALIDATION_ERROR`.
- Unknown or inaccessible reference → `404` (or `403` `LOCATION_NOT_OWNED` for citizen `nearLocationId`).
- Rows with no resolvable entity location stay in the result, sorted **last**; with `includeDistance=true`, `distance_km` is `null` for those rows.
- Agency distance uses **`head_office_location_id`** only.
- Default date/name ordering is unchanged when distance sort is not requested.

## Route index

| Area | Method | Path | Notes |
| --- | --- | --- | --- |
| Health | GET | `/health` | Public |
| Auth | POST | `/auth/register` | Public |
| Auth | POST | `/auth/login` | Public |
| Auth | POST | `/auth/refresh` | Public |
| Users | GET | `/users/me` | |
| Users | POST | `/users/:userId/roles` | Permission `auth.manage_roles` |
| Locations | POST | `/locations` | |
| Locations | GET | `/locations/my` | |
| Locations | GET | `/locations/:publicUuid` | Owner or operator |
| Intake | POST | `/intake/reports` | |
| Intake | GET | `/intake/reports/my` | |
| Intake | GET | `/intake/reports/my/stats` | |
| Intake | GET | `/intake/reports/:reportPublicUuid` | Reporter: detail + `location` |
| Intake | PATCH | `/intake/reports/:reportPublicUuid/location` | Reporter or dispatcher/system_admin |
| Intake | GET | `/intake/reports/:reportPublicUuid/reported-location-history` | Same access as patch |
| Intake | POST | `/intake/reports/:reportPublicUuid/classify/service-case` | Roles `dispatcher` / `system_admin` |
| Intake | POST | `/intake/reports/:reportPublicUuid/classify/emergency` | Same roles |
| Intake | GET | `/intake/reports/my/service-cases` | Reporter: list linked service cases |
| Intake | GET | `/intake/reports/my/incidents` | Reporter: list linked emergency incidents |
| Intake | GET | `/intake/service-cases/:publicUuid/messages` | Reporter JWT only; non-internal messages |
| Intake | POST | `/intake/service-cases/:publicUuid/messages` | Reporter JWT only (`service_cases.reporter_user_id`) |
| Intake | POST | `/intake/reports/:reportPublicUuid/escalate` | Roles `dispatcher` / `system_admin`; permissions `case.escalate` + `incident.create` |
| Operations | GET | `/operations/dispatcher/overview` | Permission `incident.classify` |
| Operations | GET | `/operations/intake-reports` | `incident.classify` |
| Operations | GET | `/operations/intake-reports/:reportPublicUuid` | `incident.classify` |
| Operations | GET | `/operations/intake-reports/:reportPublicUuid/reported-location-history` | `incident.classify` |
| Operations | POST | `/operations/intake-reports/:reportPublicUuid/promote/emergency` | `incident.create` + `incident.classify` |
| Operations | POST | `/operations/gateway/999/intake-and-incident` | `incident.classify` |
| Operations | POST | `/operations/incidents` | `incident.create` |
| Operations | GET | `/operations/incidents` | `incident.create` or `incident.update_status` |
| Operations | GET | `/operations/incidents/:incidentPublicUuid` | Same |
| Operations | PATCH | `/operations/incidents/:incidentPublicUuid/status` | `incident.update_status` |
| Operations | GET | `/operations/incidents/:incidentPublicUuid/notes` | `incident.create` or `incident.update_status` |
| Operations | POST | `/operations/incidents/:incidentPublicUuid/notes` | `incident.update_status` |
| Operations | POST | `/operations/incidents/:incidentPublicUuid/intake-reports` | `incident.create` or `incident.update_status` |
| Operations | POST | `/operations/incidents/:incidentPublicUuid/agencies` | `incident.assign_agency` |
| Operations | GET | `/operations/units/available` | `dispatch.create`; query `incidentPublicUuid` required |
| Operations | POST | `/operations/incidents/:incidentPublicUuid/dispatches` | `dispatch.create` |
| Operations | PATCH | `/operations/dispatches/:dispatchPublicUuid/status` | `dispatch.update_status` |
| Operations | GET | `/operations/agencies/workload` | `dispatch.create` or `incident.assign_agency` |
| Operations | GET | `/operations/incidents/:incidentPublicUuid/response-timing` | `dispatch.create` or `incident.assign_agency` |
| Admin | POST | `/admin/agencies/onboard` | `agency.manage` |
| Admin | GET | `/admin/agencies` | `agency.manage` |
| Admin | GET | `/admin/agencies/:agencyPublicUuid` | `agency.manage` |
| Admin | PATCH | `/admin/agencies/:agencyPublicUuid` | `agency.manage` |
| Admin | PATCH | `/admin/agencies/:agencyPublicUuid/deactivate` | `agency.manage` |
| Admin | PATCH | `/admin/agencies/:agencyPublicUuid/activate` | `agency.manage` |
| Admin | POST | `/admin/agencies/:agencyPublicUuid/representatives` | `agency.manage` |
| Admin | GET | `/admin/agencies/:agencyPublicUuid/representatives` | `agency.manage` |
| Admin | PATCH | `/admin/agency-memberships/:membershipPublicUuid/deactivate` | `agency.manage` |
| Agency | GET | `/agency/me` | `agency.view_own` + active membership |
| Agency | GET | `/agency/incidents` | `dispatch.view_own_agency` |
| Agency | GET | `/agency/dispatches` | `dispatch.view_own_agency` |
| Agency | PATCH | `/agency/dispatches/:dispatchPublicUuid/status` | `dispatch.update_own_agency` |
| Agency | GET | `/agency/units` | `agency.view_own` |
| Agency | POST | `/agency/units` | `agency.manage_own_units` |
| Agency | PATCH | `/agency/units/:unitPublicUuid` | `agency.manage_own_units` |
| Agency | PATCH | `/agency/units/:unitPublicUuid/deactivate` | `agency.manage_own_units` |
| Agency | PATCH | `/agency/units/:unitPublicUuid/status` | `agency.manage_own_units` |
| Agency | GET | `/agency/incidents/:incidentPublicUuid/notes` | `dispatch.view_own_agency` |
| Agency | GET | `/agency/incidents/:incidentPublicUuid/response-logs` | `dispatch.view_own_agency` |
| Agency | POST | `/agency/incidents/:incidentPublicUuid/response-logs` | `response_log.create_own_agency` |
| Operations | GET | `/operations/service-cases` | Permission `case.respond` |
| Operations | GET | `/operations/service-cases/:publicUuid` | `case.respond` |
| Operations | GET | `/operations/service-cases/:publicUuid/messages` | `case.respond`; message thread only |
| Operations | PATCH | `/operations/service-cases/:publicUuid/status` | `case.respond` |
| Operations | POST | `/operations/service-cases/:publicUuid/messages` | `case.respond` |
| Operations | POST | `/operations/service-cases/:publicUuid/assignments` | `case.assign` |
| Operations | POST | `/operations/service-cases/:publicUuid/resolve` | `case.respond` |

---

## Health

### GET `/health`

Checks API and database connectivity. Public.

**Response (200):**

```json
{
  "status": "RUNNING",
  "timestamp": "5/3/2026, 10:00:00 PM",
  "dbTime": "2026-05-03T16:00:00.000Z",
  "dbVersion": "8.0.36"
}
```

---

## Authentication

### POST `/auth/register`

Creates a user and returns tokens plus public `user`.

Registration sets `users.account_status` to **`active`** so the account can log in immediately (the SQL default for the column is `pending_verification`; the app overrides it for this MVP).

**Body:**

```json
{
  "email": "john@example.com",
  "fullName": "John Doe",
  "phoneNumber": "01700000000",
  "password": "StrongPass123",
  "rePassword": "StrongPass123"
}
```

`phoneNumber` must be exactly 11 digits.

**Response (201):** [auth token response](#example-auth-token-response-register-login-refresh) with `"message": "User registered successfully"`.

```json
{
  "message": "User registered successfully",
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "email": "john@example.com",
    "full_name": "John Doe",
    "phone_number": "01700000000",
    "account_status": "active",
    "is_active": true,
    "created_at": "2026-05-04T10:00:00.000Z",
    "updated_at": "2026-05-04T10:00:00.000Z"
  },
  "authz": {
    "roleCodes": ["citizen"],
    "permissions": []
  }
}
```

**Example error (409):**

```json
{
  "error": {
    "code": "EXISTING_EMAIL",
    "message": "Email already in use"
  }
}
```

### POST `/auth/login`

**Body:**

```json
{
  "email": "john@example.com",
  "password": "StrongPass123"
}
```

**Response (200):** [auth token response](#example-auth-token-response-register-login-refresh) with `"message": "Login successful"`.

**Example error (401):**

```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password"
  }
}
```

### POST `/auth/refresh`

**Body:**

```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200):** [auth token response](#example-auth-token-response-register-login-refresh) with `"message": "Token refreshed successfully"` (new access + refresh tokens).

**Example error (401):**

```json
{
  "error": {
    "code": "INVALID_REFRESH_TOKEN",
    "message": "Invalid or expired refresh token"
  }
}
```

---

## Users

### GET `/users/me`

Returns the same `user` object as auth (no tokens).

**Response (200):**

```json
{
  "user": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "email": "john@example.com",
    "full_name": "John Doe",
    "phone_number": "01700000000",
    "account_status": "active",
    "is_active": true,
    "created_at": "2026-05-04T10:00:00.000Z",
    "updated_at": "2026-05-04T10:00:00.000Z"
  },
  "authz": {
    "roleCodes": ["citizen"],
    "permissions": []
  }
}
```

**Example error (401):** `AUTH_HEADER_INVALID`.

### POST `/users/:userId/roles`

Assigns a role to another user by **target user public UUID**.

- **Permission:** `auth.manage_roles`

**Body:**

```json
{
  "roleCode": "dispatcher"
}
```

`roleCode` is normalized to lowercase.

**Response (200):**

```json
{
  "message": "Role assigned successfully",
  "userId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "roleCode": "dispatcher"
}
```

**Errors:** `403` `FORBIDDEN`, `404` `ROLE_NOT_FOUND`, etc.

---

## Locations

Citizen-owned saved locations; `public_uuid` is used as **`locationId`** on intake.

### POST `/locations`

**Body:** structured location (see [Location payloads](#location-payloads-intake-locations-operations)); **`source`** is required.

**Example request:**

```json
{
  "latitude": 23.8103,
  "longitude": 90.4125,
  "place_name": "Home",
  "source": "user_shared"
}
```

**Response (201):**

```json
{
  "message": "Location created",
  "location": {
    "id": 1,
    "publicUuid": "…",
    "latitude": 23.8103,
    "longitude": 90.4125,
    "addressText": "…",
    "placeName": null,
    "adminAreaId": 1,
    "source": "user_shared",
    "createdByUserId": 1,
    "createdAt": "…",
    "adminAreaResolved": true,
    "adminAreaMatchedLevel": "division"
  }
}
```

Field names are **camelCase** in JSON.

### GET `/locations/my`

Query (optional distance sort): `sort=distance_asc`, `nearLocationId` (numeric `id` from this list), `includeDistance=true`.

**Response (200):**

```json
{
  "locations": [
    {
      "id": 1,
      "publicUuid": "c2a9f1b0-4d3e-4c1a-9f2b-8e7d6c5b4a30",
      "latitude": 23.8103,
      "longitude": 90.4125,
      "addressText": "House 12, Road 3, Dhanmondi, Dhaka",
      "placeName": null,
      "adminAreaId": 1,
      "source": "user_shared",
      "createdByUserId": 1,
      "createdAt": "2026-05-04T11:00:00.000Z",
      "adminAreaResolved": true,
      "adminAreaMatchedLevel": "division"
    }
  ]
}
```

### GET `/locations/:publicUuid`

**Access:** location owner, or caller with `incident.classify` / `incident.create`.

**Response (200):**

```json
{
  "location": {
    "id": 1,
    "publicUuid": "c2a9f1b0-4d3e-4c1a-9f2b-8e7d6c5b4a30",
    "latitude": 23.8103,
    "longitude": 90.4125,
    "addressText": "House 12, Road 3, Dhanmondi, Dhaka",
    "placeName": null,
    "adminAreaId": 1,
    "source": "user_shared",
    "createdByUserId": 1,
    "createdAt": "2026-05-04T11:00:00.000Z",
    "adminAreaResolved": true,
    "adminAreaMatchedLevel": "division"
  }
}
```

**Response (404):** `LOCATION_NOT_FOUND`

---

## Intake (reporter)

All routes require a valid JWT. Classification routes additionally require roles **`dispatcher`** or **`system_admin`** (not only permissions).

Implementation pointers: **INTAKE-001** / **INTAKE-002** / **INTAKE-003** in `docs/tickets-intake-gateway-fe-db.md`; repositories `intakeRepo.js`, `intakeGatewayRepo.js`.

### POST `/intake/reports`

Creates an `intake_reports` row for the authenticated reporter. Initial **`intake_status`**: `received`.

**Body:**

```json
{
  "channelCode": "web_portal",
  "categoryCode": "medical",
  "summary": "Road blocked by fallen tree",
  "description": "Optional longer text",
  "reportedAt": "2026-05-04T12:00:00.000Z",
  "location": {
    "latitude": 23.8103,
    "longitude": 90.4125,
    "address_text": "", // add only if dispatcher specifies
    "place_name": "Optional label",
    "admin_area_id": 1, // add only if dispather specifies
    "source": "user_shared"
  }
}
```

Or reference an existing citizen location:

```json
{
  "channelCode": "web_portal",
  "categoryCode": "medical",
  "summary": "Road blocked by fallen tree",
  "locationId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

**Rules:**

- `location` / `locationId`: **exactly one is required**; `locationId` is the public UUID of a saved location selected by the user in the UI (the frontend submits it automatically). Follow [Location payloads](#location-payloads-intake-locations-operations).
- Plain string `location` is **not** accepted.

**Response (201):**

```json
{
  "message": "Intake report created",
  "intake": {
    "id": 1,
    "public_uuid": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
    "report_code": "IR-MA4SJP2K-9C2E2EAA",
    "intake_status": "received",
    "reported_at": "2026-05-04T12:00:00.000Z"
  }
}
```

**Errors:** `422` `REPORT_CHANNEL_NOT_FOUND`, `REPORT_CATEGORY_NOT_FOUND`, `VALIDATION_ERROR`.

### GET `/intake/reports/my`

Newest first. List items use snake_case fields. Each row includes **`location`**: a structured object or `null` when there is no reported location (same fields as **`GET /intake/reports/:reportPublicUuid`**; see [Location payloads](#location-payloads-intake-locations-operations)).

**Response (200):**

```json
{
  "reports": [
    {
      "public_uuid": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
      "report_code": "IR-MA4SJP2K-9C2E2EAA",
      "summary": "Road blocked by fallen tree",
      "description": "Optional longer text",
      "intake_status": "received",
      "final_disposition": null,
      "reported_at": "2026-05-04T12:00:00.000Z",
      "created_at": "2026-05-04T12:00:00.000Z",
      "channel_code": "web_portal",
      "category_code": "medical",
      "location": {
        "public_uuid": "c2a9f1b0-4d3e-4c1a-9f2b-8e7d6c5b4a30",
        "latitude": 23.7461,
        "longitude": 90.3742,
        "address_text": "House 12, Road 3, Dhanmondi, Dhaka",
        "place_name": null,
        "admin_area_id": 1,
        "source": "user_shared"
      }
    }
  ]
}
```

### GET `/intake/reports/my/stats`

**Response (200):**

```json
{
  "stats": {
    "totalReports": 5,
    "pendingReports": 3,
    "resolvedReports": 2
  }
}
```

### GET `/intake/reports/:reportPublicUuid`

Reporter-only detail for one report.

**Response (200):**

```json
{
  "report": {
    "public_uuid": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
    "report_code": "IR-MA4SJP2K-9C2E2EAA",
    "summary": "Road blocked by fallen tree",
    "description": "Optional longer text",
    "intake_status": "received",
    "final_disposition": null,
    "reported_at": "2026-05-04T12:00:00.000Z",
    "created_at": "2026-05-04T12:00:00.000Z",
    "channel_code": "web_portal",
    "category_code": "medical",
    "location": {
      "public_uuid": "c2a9f1b0-4d3e-4c1a-9f2b-8e7d6c5b4a30",
      "latitude": 23.7461,
      "longitude": 90.3742,
      "address_text": "House 12, Road 3, Dhanmondi, Dhaka",
      "place_name": null,
      "admin_area_id": 1,
      "source": "user_shared"
    },
    "location_text": "House 12, Road 3, Dhanmondi, Dhaka"
  }
}
```

**Response (404):** `INTAKE_REPORT_NOT_FOUND`

### PATCH `/intake/reports/:reportPublicUuid/location`

Updates **only** the report’s reported location.

**Who:** report owner (**citizen**), or **`dispatcher`** / **`system_admin`**.

**Body (exactly one of):**

```json
{ "location": { "latitude": 23.81, "longitude": 90.41, "address_text": "…" } }
```

or

```json
{ "locationId": "uuid-of-existing-location" }
```

Effective location changes append **`intake_report_location_history`**.

**Response (200):**

```json
{
  "message": "Reported location updated",
  "report": {
    "public_uuid": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
    "report_code": "IR-MA4SJP2K-9C2E2EAA",
    "summary": "Road blocked by fallen tree",
    "intake_status": "received",
    "location": {
      "public_uuid": "c2a9f1b0-4d3e-4c1a-9f2b-8e7d6c5b4a30",
      "latitude": 23.81,
      "longitude": 90.41,
      "address_text": "Updated address",
      "place_name": null,
      "admin_area_id": 1,
      "source": "user_shared"
    },
    "location_text": "Updated address"
  }
}
```

### GET `/intake/reports/:reportPublicUuid/reported-location-history`

History ordered by **`changed_at` descending** (newest change first).

Each element includes:

- `change_kind`: `initial_create` \| `location_patch`
- `location`, `previous_location` (nullable)
- `changed_by`: `{ public_uuid, full_name, actor_kind }` where `actor_kind` is `dispatcher` (includes system-admin operators in current mapping) or `citizen`

**Response (200):**

```json
{
  "history": [
    {
      "id": "2",
      "change_kind": "location_patch",
      "changed_at": "2026-05-04T13:00:00.000Z",
      "change_reason": null,
      "changed_by": {
        "public_uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "full_name": "John Doe",
        "actor_kind": "citizen"
      },
      "location": {
        "public_uuid": "c2a9f1b0-4d3e-4c1a-9f2b-8e7d6c5b4a30",
        "latitude": 23.81,
        "longitude": 90.41,
        "address_text": "Updated address",
        "place_name": null,
        "admin_area_id": 1,
        "source": "user_shared"
      },
      "previous_location": {
        "public_uuid": "b1a8e0c9-3c2d-4b0a-8e1f-7d6c5b4a3029",
        "latitude": 23.7461,
        "longitude": 90.3742,
        "address_text": "House 12, Road 3, Dhanmondi, Dhaka",
        "place_name": null,
        "admin_area_id": 1,
        "source": "user_shared"
      }
    }
  ]
}
```

Returns `{ "history": [] }` when allowed but no history rows exist.

### POST `/intake/reports/:reportPublicUuid/classify/service-case`

Branches intake → **service case**. Requires **`reported_location_id`** on the intake (otherwise classification fails with an appropriate business/validation error).

**Body:**

```json
{
  "title": "Optional override title",
  "description": "Optional",
  "priorityLevel": "medium"
}
```

`priorityLevel`: `low` \| `medium` \| `high` \| `urgent` (optional).

**Response (201):**

```json
{
  "message": "Intake classified as service case",
  "service_case": {
    "id": 1,
    "public_uuid": "sc000001-0000-4000-8000-000000000001",
    "case_code": "SC-MA4SJP2K-9C2E2EAA",
    "title": "Road blocked by fallen tree",
    "priority_level": "medium",
    "current_status_id": 2
  },
  "intake": {
    "id": 1,
    "public_uuid": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
    "report_code": "IR-MA4SJP2K-9C2E2EAA",
    "intake_status": "linked_to_case"
  }
}
```

`service_case` and `intake` are DB-shaped rows (snake_case column names).

**Errors:** `409` `INTAKE_NOT_CLASSIFIABLE`, `422` e.g. `SERVICE_CASE_REQUIRES_REPORTER_USER`, `403` if not dispatcher/system_admin.

### POST `/intake/reports/:reportPublicUuid/classify/emergency`

Branches intake → **999 / emergency** path (`emergency_calls`, `emergency_incidents`, `incident_report_links`; intake moves toward `linked_to_incident`). **Roles:** dispatcher / system_admin only.

**Body:**

```json
{
  "severityCode": "high",
  "incidentTitle": "Optional override",
  "incidentDescription": "Optional",
  "callerPhoneNumber": "01700000000",
  "callStartedAt": "2026-05-04T12:05:00.000Z",
  "reportedAt": "2026-05-04T12:05:00.000Z"
}
```

`severityCode`: `low` \| `medium` \| `high` \| `critical`. `reportedAt` is optional here (also used by some promote flows sharing validation).

**Response (201):**

```json
{
  "message": "Intake classified on emergency (999) path",
  "emergency_call": {
    "id": 1,
    "public_uuid": "ec000001-0000-4000-8000-000000000001",
    "call_status": "triaged"
  },
  "emergency_incident": {
    "id": 1,
    "public_uuid": "e5000001-0000-4000-8000-000000000099",
    "incident_code": "EI-MA4SJP2K-9C2E2EAA",
    "title": "Road blocked by fallen tree",
    "severity_code": "high"
  },
  "incident_report_link": {
    "id": 1,
    "link_type": "primary_report"
  },
  "intake": {
    "public_uuid": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
    "intake_status": "linked_to_incident"
  }
}
```

**Errors:** `422` `EMERGENCY_INCIDENT_REQUIRES_LOCATION` when intake has no location, `403` for role.

---

## Operations

Permissions are enforced per route (see [Route index](#route-index)).

### GET `/operations/dispatcher/overview`

Rollup for dispatcher UIs: **counts** + merged **recent** timeline (intakes pending classification, non-terminal incidents, open service cases). Requires **`incident.classify`**.

**Count semantics:**

| Field | Meaning |
| --- | --- |
| `intake_reports_pending_classification` | `intake_status` in `received` or `under_review` |
| `incidents_active` | current incident status `is_terminal = false` |
| `service_cases_open` | current case status `is_terminal = false` |

**Recent:** up to 10 per source, merged by `occurred_at`, capped at **15** items. Each item: `kind` (`intake_report` \| `incident` \| `service_case`), `public_uuid`, `summary`, `status`, `category`, `occurred_at`, `age_minutes`.

**Response (200):**

```json
{
  "counts": {
    "intake_reports_pending_classification": 2,
    "incidents_active": 5,
    "service_cases_open": 4
  },
  "recent": [
    {
      "kind": "incident",
      "public_uuid": "f3c2bb6c-1111-4a2e-9c61-aaaaaaaaaaaa",
      "summary": "Power line down",
      "status": "classified",
      "category": "infrastructure_emergency",
      "occurred_at": "2026-05-06T07:41:03.000Z",
      "age_minutes": 18
    }
  ]
}
```

### GET `/operations/intake-reports`

Queue of intake reports. Query: `intake_status`, `categoryCode`, `limit` (1–100, default 50), `offset`, `sort` (`reported_at_desc` \| `reported_at_asc` \| `distance_asc`). For `distance_asc`, require `nearIncidentPublicUuid` and optional `includeDistance=true`.

**Response (200):**

```json
{
  "intake_reports": [
    {
      "public_uuid": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
      "report_code": "IR-MA4SJP2K-9C2E2EAA",
      "reporter_user_id": "42",
      "summary": "Road blocked by fallen tree",
      "description": null,
      "intake_status": "received",
      "final_disposition": null,
      "channel_code": "web_portal",
      "category_code": "medical",
      "location": {
        "public_uuid": "c2a9f1b0-4d3e-4c1a-9f2b-8e7d6c5b4a30",
        "latitude": 23.7461,
        "longitude": 90.3742,
        "address_text": "House 12, Road 3, Dhanmondi, Dhaka",
        "place_name": null,
        "admin_area_id": 1,
        "source": "user_shared"
      },
      "has_service_case": false,
      "has_incident": false,
      "reported_at": "2026-05-04T12:00:00.000Z",
      "created_at": "2026-05-04T12:00:00.000Z",
      "updated_at": "2026-05-04T12:00:00.000Z"
    }
  ],
  "pagination": {
    "limit": 50,
    "offset": 0,
    "total": 1
  }
}
```

### GET `/operations/intake-reports/:reportPublicUuid`

Same fields as list elements, plus optional read-only reporter/caller detail:

```json
{
  "intake_report": {
    "public_uuid": "…",
    "report_code": "IR-…",
    "reporter": {
      "user_public_uuid": "…",
      "full_name": "…",
      "phone_number": "…",
      "email": null,
      "is_anonymous": false
    },
    "emergency_call": {
      "caller_phone_number": "+8801700000000"
    }
  }
}
```

`reporter` and `emergency_call` are omitted or null when not applicable. Anonymous reports set `reporter.is_anonymous` to `true` with contact fields null.

**Response (200):**

```json
{
  "intake_report": {
    "public_uuid": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
    "report_code": "IR-MA4SJP2K-9C2E2EAA",
    "summary": "Road blocked by fallen tree",
    "intake_status": "received",
    "category_code": "medical",
    "location": {
      "public_uuid": "c2a9f1b0-4d3e-4c1a-9f2b-8e7d6c5b4a30",
      "latitude": 23.7461,
      "longitude": 90.3742,
      "address_text": "House 12, Road 3, Dhanmondi, Dhaka",
      "place_name": null,
      "admin_area_id": 1,
      "source": "user_shared"
    },
    "has_service_case": false,
    "has_incident": false,
    "reported_at": "2026-05-04T12:00:00.000Z"
  }
}
```

**Response (404):** `INTAKE_REPORT_NOT_FOUND`

### GET `/operations/intake-reports/:reportPublicUuid/reported-location-history`

Same payload shape as the reporter **`GET /intake/reports/.../reported-location-history`** (see example there), for users with **`incident.classify`**.

### POST `/operations/intake-reports/:reportPublicUuid/promote/emergency`

Creates an **`emergency_incidents`** row from an intake **without** requiring an `emergency_calls` row (link note explains promotion without call record). Intake must be promotable, must have **`reported_location_id`**, and must not already be linked to an incident.

**Permissions:** **`incident.create`** and **`incident.classify`**.

**Body:**

```json
{
  "severityCode": "high",
  "incidentTitle": "Unconscious patient near gate 2",
  "incidentDescription": "…",
  "callerPhoneNumber": "+8801700000000",
  "callStartedAt": "2026-05-04T12:03:00.000Z",
  "reportedAt": "2026-05-04T12:05:00.000Z"
}
```

**Response (201):**

```json
{
  "message": "Intake promoted to emergency incident",
  "incident": {
    "public_uuid": "e5000001-0000-4000-8000-000000000099",
    "incident_code": "EI-MA4SJP2K-9C2E2EAA",
    "title": "Unconscious patient near gate 2",
    "description": "…",
    "origin_type": "intake_promotion",
    "status_code": "classified",
    "category_code": "medical",
    "severity_code": "high",
    "outcome_code": null,
    "reported_at": "2026-05-04T12:05:00.000Z",
    "resolved_at": null,
    "closed_at": null,
    "created_at": "2026-05-04T12:05:01.000Z",
    "updated_at": "2026-05-04T12:05:01.000Z"
  }
}
```

**Errors:** `422` `EMERGENCY_INCIDENT_REQUIRES_LOCATION`, `409` `INTAKE_NOT_PROMOTABLE`, `INTAKE_ALREADY_LINKED`, …

### POST `/operations/gateway/999/intake-and-incident`

Dispatcher quick flow: creates intake on **`emergency_call`** channel, ensures emergency call placeholder, then branches to **`service_case`**, **`emergency_incident`**, or **`existing_incident`** per `disposition`.

**Body (validated):**

- `disposition`: `service_case` \| `emergency_incident` \| `existing_incident` (**required**)
- `categoryCode`, `summary` (**required**); `description`, `reportedAt` optional
- Exactly one of **`location`** or **`locationId`** (**required**)
- `callerPhoneNumber`, `callStartedAt` optional call metadata
- `incidentTitle`, `incidentDescription` optional overrides
- If `disposition === "emergency_incident"`: **`severityCode`** required (`low` \| `medium` \| `high` \| `critical`)
- If `disposition === "existing_incident"`: **`incidentPublicUuid`** required; `linkType` (`supporting_report` \| `follow_up_report`, default `supporting_report`) and `note` (max 500 chars) optional
- If `disposition === "service_case"`: **`priorityLevel`** optional (`low` \| `medium` \| `high` \| `urgent`)

**Example request (`disposition: "emergency_incident"`):**

```json
{
  "disposition": "emergency_incident",
  "categoryCode": "medical",
  "summary": "Caller reports chest pain",
  "description": "Patient conscious, difficulty breathing",
  "severityCode": "high",
  "location": {
    "latitude": 23.8103,
    "longitude": 90.4125,
    "source": "dispatcher_selected"
  },
  "callerPhoneNumber": "01700000000",
  "callStartedAt": "2026-05-04T12:03:00.000Z"
}
```

**Response (201):**

```json
{
  "message": "999 intake and incident flow completed",
  "disposition": "emergency_incident",
  "intake": {
    "public_uuid": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
    "report_code": "IR-MA4SJP2K-9C2E2EAA",
    "intake_status": "linked_to_incident"
  },
  "emergency_call": {
    "public_uuid": "ec000001-0000-4000-8000-000000000001",
    "call_status": "triaged"
  },
  "emergency_incident": {
    "public_uuid": "e5000001-0000-4000-8000-000000000099",
    "incident_code": "EI-MA4SJP2K-9C2E2EAA"
  },
  "incident_report_link": {
    "link_type": "primary_report"
  }
}
```

When `disposition` is `service_case`, the response includes `service_case` instead of `emergency_incident` / `incident_report_link`.

### POST `/operations/incidents`

**Permission:** `incident.create`.

**Mode A — link existing intake** (category + location from intake; intake must be eligible):

```json
{
  "severityCode": "high",
  "intakeReportPublicUuid": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
  "title": "Optional; defaults to intake summary",
  "description": "Optional",
  "reportedAt": "2026-05-04T12:00:00.000Z"
}
```

**Mode B — standalone** (no intake): requires **`categoryCode`**, **`title`**, and either **`location`** or **`locationId`** (structured location object, not a plain string):

```json
{
  "categoryCode": "medical",
  "severityCode": "high",
  "title": "Worker collapsed near loading dock",
  "description": "Optional",
  "reportedAt": "2026-05-04T12:00:00.000Z",
  "location": {
    "latitude": 23.8103,
    "longitude": 90.4125,
    "address_text": "House 12, Road 3, Dhanmondi, Dhaka",
    "place_name": null,
    "admin_area_id": 1,
    "source": "dispatcher_selected"
  }
}
```

**Response (201):**

```json
{
  "message": "Incident created",
  "incident": {
    "public_uuid": "e5000001-0000-4000-8000-000000000099",
    "incident_code": "EI-MA4SJP2K-9C2E2EAA",
    "title": "Worker collapsed near loading dock",
    "description": "Optional",
    "origin_type": "admin_created",
    "status_code": "classified",
    "category_code": "medical",
    "severity_code": "high",
    "outcome_code": null,
    "reported_at": "2026-05-04T12:00:00.000Z",
    "resolved_at": null,
    "closed_at": null,
    "created_at": "2026-05-04T12:00:01.000Z",
    "updated_at": "2026-05-04T12:00:01.000Z"
  }
}
```

**Errors:** `422` for `REPORT_CATEGORY_NOT_FOUND`, `LOCATION_REQUIRED`, `INCIDENT_TITLE_REQUIRED`, `EMERGENCY_INCIDENT_REQUIRES_LOCATION`, etc.

### GET `/operations/incidents`

Query: `status_code`, `reported_after`, `reported_before`, `limit`, `offset`. Default order: `reported_at` descending.

Distance sort: `sort=distance_asc`, `nearIntakeReportPublicUuid`, optional `includeDistance=true` (see [Distance sorting](#distance-sorting-list-endpoints)).

**Response (200):**

```json
{
  "incidents": [
    {
      "public_uuid": "e5000001-0000-4000-8000-000000000001",
      "incident_code": "EI-DEMO0001",
      "title": "Power line down",
      "description": null,
      "origin_type": "emergency_call",
      "status_code": "classified",
      "category_code": "infrastructure_emergency",
      "severity_code": "high",
      "reported_at": "2026-05-06T07:41:03.000Z",
      "resolved_at": null,
      "closed_at": null,
      "created_at": "2026-05-06T07:41:03.000Z",
      "updated_at": "2026-05-06T07:41:03.000Z"
    }
  ],
  "pagination": {
    "limit": 50,
    "offset": 0,
    "total": 1
  }
}
```

### GET `/operations/incidents/:incidentPublicUuid`

**Response (200):**

```json
{
  "incident": {
    "public_uuid": "e5000001-0000-4000-8000-000000000001",
    "incident_code": "EI-DEMO0001",
    "title": "Power line down",
    "description": "Sparks visible near pole 12",
    "origin_type": "emergency_call",
    "status_code": "classified",
    "category_code": "infrastructure_emergency",
    "severity_code": "high",
    "outcome_code": null,
    "reported_at": "2026-05-06T07:41:03.000Z",
    "resolved_at": null,
    "closed_at": null,
    "created_at": "2026-05-06T07:41:03.000Z",
    "updated_at": "2026-05-06T07:41:03.000Z"
  },
  "linked_intake_reports": [
    {
      "link_type": "primary_report",
      "linked_at": "2026-05-04T12:05:00.000Z",
      "link_note": null,
      "intake_public_uuid": "…",
      "intake_report_code": "IR-…",
      "intake_summary": "…",
      "intake_status": "linked_to_incident",
      "location": null
    }
  ],
  "timeline_preview": [
    {
      "id": "1",
      "event_type": "operator_note",
      "event_title": "Update",
      "event_description": null,
      "event_time": "2026-05-04T13:00:00.000Z",
      "created_at": "2026-05-04T13:00:01.000Z"
    }
  ],
  "participating_agencies": [
    {
      "agency_public_uuid": "b2000001-0000-4000-8000-000000000001",
      "agency_name": "Dhaka Fire Service",
      "agency_type_code": "fire_service",
      "is_lead_agency": true,
      "participation_status": "active",
      "joined_at": "2026-05-19T10:00:00.000Z"
    }
  ],
  "dispatches": [
    {
      "public_uuid": "f5000001-0000-4000-8000-000000000001",
      "status_code": "assigned",
      "priority_level": "high",
      "assigned_at": "2026-05-19T10:05:00.000Z",
      "dispatched_at": null,
      "arrived_at": null,
      "completed_at": null,
      "cancelled_at": null,
      "unit": {
        "public_uuid": "c3000001-0000-4000-8000-000000000001",
        "unit_code": "FIRE-01",
        "unit_name": "Fire Engine Alpha",
        "unit_type_code": "fire_truck",
        "status_code": "busy"
      },
      "owning_agency": {
        "public_uuid": "b2000001-0000-4000-8000-000000000001",
        "agency_name": "Dhaka Fire Service",
        "agency_type_code": "fire_service"
      }
    }
  ]
}
```

`incident` is the full detail DTO; timeline preview is capped (e.g. last 50 by `event_time`).

`participating_agencies` lists all rows from `incident_agency_participation` for the incident, ordered with lead agency first, then `joined_at` ascending.

`dispatches` lists all dispatches for the incident, ordered by `assigned_at` descending. Each item includes dispatch status, priority, milestone timestamps, an assigned **unit** summary, and the unit’s **owning_agency** summary. External identifiers use `public_uuid` / `*_public_uuid` only.

For seeded demo data, see incident `e5000001-0000-4000-8000-000000000001` under [Demo seed UUIDs](#demo-seed-uuids-24_seed_agencies_units_demosql).

**Response (404):** `INCIDENT_NOT_FOUND`

### PATCH `/operations/incidents/:incidentPublicUuid/status`

**Permission:** `incident.update_status`.

**Body:**

```json
{
  "statusCode": "in_progress",
  "note": "Optional note stored in status history",
  "outcomeCode": "resolved"
}
```

`outcomeCode` only when moving to **`resolved`**, **`closed`**, or **`cancelled`**: `resolved` \| `false_alarm` \| `duplicate_incident` \| `cancelled` \| `transferred` \| `unresolved`.

**Transitions (from → to):**

- `classified` → `in_progress`, `resolved`, `closed`, `cancelled` (initial status when an incident is created)
- `in_progress` → `resolved`, `closed`, `cancelled`

Terminal statuses cannot change again.

When transitioning to **`resolved`**, **`closed`**, or **`cancelled`**, the server also (same transaction):

- Finalizes all non-terminal dispatches on the incident (`completed` for `resolved`/`closed`, `cancelled` for `cancelled`), advancing through valid dispatch transitions with note `Incident <statusCode>`.
- Sets every dispatched unit that is still **`busy`** back to **`available`** via `unit_status_history`.

**Response (200):**

```json
{
  "message": "Incident status updated",
  "incident": {
    "public_uuid": "e5000001-0000-4000-8000-000000000001",
    "incident_code": "EI-DEMO0001",
    "status_code": "in_progress",
    "outcome_code": null,
    "updated_at": "2026-05-06T08:00:00.000Z"
  }
}
```

**Response (409):** `INVALID_STATUS_TRANSITION`

### GET `/operations/incidents/:incidentPublicUuid/notes`

**Permission:** `incident.create` or `incident.update_status`.

Lists operator notes for the incident (`event_type = operator_note` in `incident_timeline_events`), newest first. Unlike `timeline_preview` on incident detail, this endpoint is paginated and returns notes only.

**Query:** `limit` (1–100, default 20), `offset` (default 0).

**Response (200):**

```json
{
  "incident_public_uuid": "e5000001-0000-4000-8000-000000000001",
  "limit": 20,
  "offset": 0,
  "notes": [
    {
      "id": "1",
      "event_type": "operator_note",
      "event_title": "Radio check",
      "event_description": "Optional body",
      "event_time": "2026-05-04T14:00:00.000Z",
      "created_at": "2026-05-04T13:00:01.000Z"
    }
  ]
}
```

**Response (404):** `INCIDENT_NOT_FOUND`

### POST `/operations/incidents/:incidentPublicUuid/notes`

**Permission:** `incident.update_status`.

**Body:**

```json
{
  "title": "Radio check",
  "description": "Optional body",
  "eventTime": "2026-05-04T14:00:00.000Z"
}
```

`title` required (max 255). `eventTime` optional ISO datetime; defaults to now.

**Response (201):**

```json
{
  "message": "Operator note added",
  "note": {
    "id": "12",
    "event_type": "operator_note",
    "event_title": "Radio check",
    "event_description": "Optional body",
    "event_time": "2026-05-04T14:00:00.000Z",
    "created_at": "2026-05-04T14:00:01.000Z"
  }
}
```

### POST `/operations/incidents/:incidentPublicUuid/intake-reports`

Links another intake to an existing incident. **Does not** move the incident’s primary location.

**Body:**

```json
{
  "intakeReportPublicUuid": "required-uuid",
  "linkType": "supporting_report",
  "note": "Optional, max 500 chars"
}
```

`linkType`: `supporting_report` \| `follow_up_report` (optional; default `supporting_report`).

Intake must have a location and must not already be linked (`422` / `409` as applicable).

**Response (201):**

```json
{
  "message": "Intake report linked to incident",
  "link": {
    "id": 5,
    "link_type": "supporting_report",
    "linked_at": "2026-05-04T15:00:00.000Z",
    "note": null,
    "incident_public_uuid": "e5000001-0000-4000-8000-000000000001",
    "incident_code": "EI-DEMO0001",
    "intake_report_public_uuid": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
    "intake_report_code": "IR-MA4SJP2K-9C2E2EAA"
  }
}
```

---

## Operations — dispatch workflow

Dispatcher flow: add participating agency → list available units for the incident → create dispatch → advance dispatch status. Status values are **strings** (`status_code`). External identifiers use `public_uuid`.

Incident status may auto-advance on milestones (same transaction): agency add → `agency_assigned`; dispatch create → `unit_assigned`; dispatch `dispatched` → `dispatched`; dispatch `arrived` → `in_progress`. `completed` / `cancelled` do not change incident status.

### Demo seed UUIDs (`24_seed_agencies_units_demo.sql`)

| Entity | `public_uuid` | Notes |
|--------|---------------|--------|
| Dhaka Fire Service | `b2000001-0000-4000-8000-000000000001` | Agency |
| Dhaka Metropolitan Police | `b2000001-0000-4000-8000-000000000002` | Agency |
| Dhaka Emergency Medical Services | `b2000001-0000-4000-8000-000000000003` | Agency |
| Fire Engine Alpha | `c3000001-0000-4000-8000-000000000001` | Unit, `available` |
| Fire Engine Bravo | `c3000001-0000-4000-8000-000000000002` | Unit, `available` |
| Patrol Unit One | `c3000001-0000-4000-8000-000000000003` | Unit, `available` |
| Patrol Unit Two | `c3000001-0000-4000-8000-000000000004` | Unit, `busy` |
| Ambulance One | `c3000001-0000-4000-8000-000000000005` | Unit, `available` |
| Ambulance Two | `c3000001-0000-4000-8000-000000000006` | Unit, `available` |
| Medical Response Van | `c3000001-0000-4000-8000-000000000007` | Unit, `busy` |
| Fire Command Vehicle | `c3000001-0000-4000-8000-000000000008` | Unit, `available` |

### POST `/operations/incidents/:incidentPublicUuid/agencies`

**Permission:** `incident.assign_agency`.

**Body:**

```json
{
  "agencyPublicUuid": "b2000001-0000-4000-8000-000000000001",
  "isLeadAgency": false
}
```

**Response (201):**

```json
{
  "message": "Agency added to incident",
  "participation": {
    "agency_public_uuid": "…",
    "agency_name": "Dhaka Fire Service",
    "agency_type_code": "fire_service",
    "is_lead_agency": false,
    "participation_status": "active",
    "joined_at": "2026-05-19T10:00:00.000Z"
  }
}
```

**Errors:** `404 INCIDENT_NOT_FOUND`, `404 AGENCY_NOT_FOUND`, `409 AGENCY_ALREADY_PARTICIPATING`

### GET `/operations/units/available`

**Permission:** `dispatch.create`.

**Query:** `incidentPublicUuid` (required UUID) — only units whose agency participates on the incident (`participation_status` `requested` or `active`) and `status_code` = `available`. Optional `sort=distance_asc` sorts by distance from that incident’s location; optional `includeDistance=true`.

**Response (200):**

```json
{
  "incident_public_uuid": "…",
  "units": [
    {
      "public_uuid": "c3000001-0000-4000-8000-000000000001",
      "unit_code": "FIRE-01",
      "unit_name": "Fire Engine Alpha",
      "status_code": "available",
      "agency_public_uuid": "b2000001-0000-4000-8000-000000000001",
      "agency_name": "Dhaka Fire Service",
      "unit_type_code": "fire_truck"
    }
  ]
}
```

**Errors:** `404 INCIDENT_NOT_FOUND`, `422 VALIDATION_ERROR` (missing/invalid query)

### POST `/operations/incidents/:incidentPublicUuid/dispatches`

**Permission:** `dispatch.create`.

Creates dispatch in `assigned`, sets unit to `busy`, and may advance incident to `unit_assigned`.

**Body:**

```json
{
  "unitPublicUuid": "c3000001-0000-4000-8000-000000000001",
  "priorityLevel": "medium",
  "note": "Optional"
}
```

`priorityLevel`: `low` \| `medium` \| `high` \| `critical` (default `medium`).

**Response (201):**

```json
{
  "message": "Dispatch created",
  "dispatch": {
    "public_uuid": "…",
    "incident_public_uuid": "…",
    "unit_public_uuid": "…",
    "status_code": "assigned",
    "priority_level": "medium",
    "assigned_at": "2026-05-19T10:05:00.000Z",
    "dispatched_at": null,
    "arrived_at": null,
    "completed_at": null,
    "cancelled_at": null
  }
}
```

**Errors:** `404 INCIDENT_NOT_FOUND`, `404 UNIT_NOT_FOUND`, `409 UNIT_NOT_AVAILABLE`, `409 AGENCY_NOT_PARTICIPATING`, `409 DISPATCH_ALREADY_EXISTS`

### PATCH `/operations/dispatches/:dispatchPublicUuid/status`

**Permission:** `dispatch.update_status`.

**Body:**

```json
{
  "statusCode": "dispatched",
  "note": "Optional"
}
```

`statusCode`: `dispatched` \| `arrived` \| `completed` \| `cancelled`.

**Dispatch transitions:**

- `assigned` → `dispatched`, `cancelled`
- `dispatched` → `arrived`, `cancelled`
- `arrived` → `completed`, `cancelled`

On `completed` or `cancelled`, unit returns to `available`.

**Response (200):**

```json
{
  "message": "Dispatch status updated",
  "dispatch": {
    "public_uuid": "f5000001-0000-4000-8000-000000000001",
    "incident_public_uuid": "e5000001-0000-4000-8000-000000000001",
    "unit_public_uuid": "c3000001-0000-4000-8000-000000000001",
    "status_code": "dispatched",
    "priority_level": "high",
    "assigned_at": "2026-05-19T10:05:00.000Z",
    "dispatched_at": "2026-05-19T10:10:00.000Z",
    "arrived_at": null,
    "completed_at": null,
    "cancelled_at": null
  }
}
```

**Errors:** `404 DISPATCH_NOT_FOUND`, `409 INVALID_STATUS_TRANSITION`, `422 INVALID_STATUS_CODE`

### GET `/operations/agencies/workload`

**Permission:** `dispatch.create` or `incident.assign_agency`.

Reads `vw_agency_workload` joined with agency `public_uuid`. Default order: agency name. Distance sort: `sort=distance_asc`, `nearIncidentPublicUuid`, optional `includeDistance=true` (agency point = head office).

**Response (200):**

```json
{
  "agencies": [
    {
      "agency_public_uuid": "…",
      "agency_name": "Dhaka Fire Service",
      "active_incidents": 0,
      "total_units": 3,
      "available_units": 2,
      "busy_units": 1,
      "total_dispatches": 0
    }
  ]
}
```

### GET `/operations/incidents/:incidentPublicUuid/response-timing`

**Permission:** `dispatch.create` or `incident.assign_agency`.

Reads `vw_response_pipeline_timing` for pipeline SLA minutes.

**Response (200):**

```json
{
  "timing": {
    "incident_public_uuid": "…",
    "incident_code": "EI-…",
    "first_call_started_at": null,
    "incident_created_at": "2026-05-19T10:00:00.000Z",
    "first_agency_joined_at": null,
    "first_unit_assigned_at": null,
    "first_unit_dispatched_at": null,
    "first_unit_arrived_at": null,
    "call_to_incident_minutes": null,
    "incident_to_agency_minutes": null,
    "agency_to_dispatch_minutes": null,
    "dispatch_to_arrival_minutes": null
  }
}
```

**Errors:** `404 INCIDENT_NOT_FOUND`

---

## Intake — citizen service cases

### GET `/intake/reports/my/service-cases`

Lists **service cases** where the authenticated user is the reporter (`service_cases.reporter_user_id`). Newest by `updated_at` first.

**Response (200):**

```json
{
  "service_cases": [
    {
      "public_uuid": "…",
      "case_code": "SC-…",
      "title": "…",
      "description": null,
      "priority_level": "medium",
      "status_code": "under_review",
      "category_code": "medical",
      "intake_public_uuid": "…",
      "intake_report_code": "IR-…",
      "last_updated": "2026-05-06T12:00:00.000Z",
      "created_at": "2026-05-06T10:00:00.000Z",
      "location": {
        "public_uuid": "…",
        "latitude": 23.81,
        "longitude": 90.41,
        "address_text": "…",
        "place_name": null,
        "admin_area_id": 1,
        "source": "user_shared"
      },
      "location_text": "…"
    }
  ]
}
```

`location` is taken from `COALESCE(service_cases.current_location_id, intake_reports.reported_location_id)` when present.

---

## Intake — citizen incidents

### GET `/intake/reports/my/incidents`

Lists **emergency incidents** linked to intake reports where the authenticated user is the reporter (`intake_reports.reporter_user_id` via `incident_report_links`). Newest by `updated_at` first.

When multiple intake reports from the same reporter link to one incident, the list uses the `primary_report` link when present; otherwise the earliest `linked_at`.

**Response (200):**

```json
{
  "incidents": [
    {
      "public_uuid": "…",
      "incident_code": "EMI-…",
      "title": "…",
      "description": null,
      "status_code": "active",
      "category_code": "medical",
      "severity_code": "high",
      "origin_type": "emergency_call",
      "intake_public_uuid": "…",
      "intake_report_code": "IR-…",
      "reported_at": "2026-05-06T10:00:00.000Z",
      "created_at": "2026-05-06T10:00:00.000Z",
      "last_updated": "2026-05-06T12:00:00.000Z",
      "resolved_at": null,
      "closed_at": null,
      "location": {
        "public_uuid": "…",
        "latitude": 23.81,
        "longitude": 90.41,
        "address_text": "…",
        "place_name": null,
        "admin_area_id": 1,
        "source": "user_shared"
      },
      "location_text": "…"
    }
  ]
}
```

`location` is taken from `COALESCE(emergency_incidents.current_location_id, intake_reports.reported_location_id)` when present.

### GET `/intake/service-cases/:publicUuid/messages`

**Access:** Bearer JWT. The authenticated user must be the case reporter (`service_cases.reporter_user_id` matches the token’s internal user id).

**Behavior:** Returns the message thread for the service case, oldest first. Rows with `is_internal = TRUE` are **excluded** (citizens never see internal operator notes).

**Response (200):**

```json
{
  "public_uuid": "…",
  "case_code": "SC-…",
  "messages": [
    {
      "id": "1",
      "message_type": "user_message",
      "subject": "…",
      "body": "…",
      "created_at": "2026-05-19T14:00:00.000Z",
      "sender": { "public_uuid": "…", "full_name": "…" }
    }
  ]
}
```

`message_type` is one of `user_message`, `admin_reply`, or `system_note`. `sender` is `null` for system-generated rows without a user.

**Errors:**

- `401` — missing/invalid bearer token.
- `403` `FORBIDDEN` — case exists but caller is not the reporter.
- `404` `SERVICE_CASE_NOT_FOUND` — unknown `publicUuid`.
- `422` `VALIDATION_ERROR` — invalid `publicUuid` param.

### POST `/intake/service-cases/:publicUuid/messages`

**Access:** Bearer JWT. The authenticated user must be the case reporter (`service_cases.reporter_user_id` matches the token’s internal user id).

**Body:**

```json
{
  "title": "Additional details",
  "description": "The water leak is getting worse"
}
```

`title` required (trimmed, max 255); `description` optional. Stored as `subject` + `body` on `case_messages`.

**Behavior (single DB transaction for case writes):** Inserts `case_messages` with `message_type` **`user_message`**. If the case’s current status is **`awaiting_user_response`**, the server also moves status to **`under_review`** and writes audit rows. Notification to active assignee is best-effort after commit.

**Response (201):**

```json
{
  "message": "Citizen reply recorded",
  "case_message": {
    "id": "15",
    "message_type": "user_message",
    "subject": "Additional details",
    "body": "The water leak is getting worse",
    "created_at": "2026-05-19T15:00:00.000Z"
  }
}
```

**Errors:**

- `401` — missing/invalid `Authorization` bearer token.
- `403` `FORBIDDEN` — service case exists but the caller is not the reporter (`"You are not the reporter for this service case"`).
- `404` `SERVICE_CASE_NOT_FOUND` — unknown `publicUuid`.
- `409` `SERVICE_CASE_NOT_UPDATABLE` — terminal case (cannot add messages).
- `422` `VALIDATION_ERROR` — invalid body or invalid `publicUuid` param.

### POST `/intake/reports/:reportPublicUuid/escalate`

Promotes an intake that is already on the **service case** path (`intake_status` must be `linked_to_case`) to an **emergency incident**, with a linked `case_escalations` row and case status `escalated_to_emergency`. **Roles:** `dispatcher` or `system_admin`. **Permissions:** `case.escalate` **and** `incident.create`.

**Body:**

```json
{
  "severityCode": "high",
  "incidentTitle": "Flooding blocking exit",
  "incidentDescription": "Water level rising rapidly",
  "reportedAt": "2026-05-06T14:00:00.000Z",
  "escalationReason": "Citizen at risk; requires emergency response"
}
```

`escalationReason` is required (1–1000 chars).

**Location rule:** the incident’s primary `locations.id` is the **latest** row in `intake_report_location_history` for this intake (by `changed_at`), else `intake_reports.reported_location_id`, else `service_cases.current_location_id`. The same `locations` row is referenced in `incident_location_history` with `is_current = TRUE` (no geometry copy).

**Response (201):**

```json
{
  "message": "Service case escalated to emergency incident",
  "intake_public_uuid": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
  "incident": {
    "public_uuid": "e5000001-0000-4000-8000-000000000088",
    "incident_code": "EI-ESC0001",
    "title": "Flooding blocking exit",
    "origin_type": "service_case_escalation",
    "status_code": "classified",
    "severity_code": "high"
  },
  "service_case": {
    "public_uuid": "sc000001-0000-4000-8000-000000000001",
    "case_code": "SC-MA4SJP2K-9C2E2EAA",
    "status_code": "escalated_to_emergency"
  }
}
```

**Errors:** `404` `INTAKE_REPORT_NOT_FOUND`, `409` `INTAKE_NOT_ESCALATABLE`, `INTAKE_NOT_LINKED_TO_SERVICE_CASE`, `CASE_ALREADY_ESCALATED`, `INTAKE_ALREADY_LINKED`, `422` `EMERGENCY_INCIDENT_REQUIRES_LOCATION`, `403` for role/permission.

---

## Operations — service cases

**Note:** Database tables `work_queues` and `queue_items` exist for future workload features; **these HTTP endpoints do not read or write them**. The operator queue is the paginated **`GET /operations/service-cases`** list.

**Dispatcher / operator messages:** The API accepts JSON `title` + optional `description`; persisted as `case_messages.subject` and `case_messages.body`. Responses and case detail `messages[]` return `subject` and `body`. Persisted `message_type` for dispatcher POST is **`admin_reply`** (dispatcher/operator reply in the DB enum).

**Case message object** (used in GET message endpoints and in `messages[]` on case detail):

| Field | Type | Notes |
|-------|------|--------|
| `id` | string | `case_messages.id` |
| `message_type` | string | `user_message` \| `admin_reply` \| `system_note` |
| `subject` | string | |
| `body` | string \| null | |
| `created_at` | string (ISO) | |
| `sender` | object \| null | `{ public_uuid, full_name }` |
| `is_internal` | boolean | **Operations only** (GET messages + case detail); omitted on citizen GET |

### GET `/operations/service-cases`

**Permission:** `case.respond`.

**Query:** `status` (case `status_code` filter), `categoryCode`, `assignedTo` (operator user **public UUID** — matches active `case_assignments`), `limit` (1–100, default 50), `offset` (default 0).

**Order:** `service_cases.updated_at` descending (exposed per row as `last_updated`).

**Response (200):**

```json
{
  "service_cases": [
    {
      "public_uuid": "sc000001-0000-4000-8000-000000000001",
      "case_code": "SC-MA4SJP2K-9C2E2EAA",
      "title": "Water leak in basement",
      "description": null,
      "priority_level": "medium",
      "status_code": "under_review",
      "category_code": "utilities",
      "last_updated": "2026-05-06T12:00:00.000Z",
      "created_at": "2026-05-06T10:00:00.000Z",
      "assigned_to_user_public_uuid": "d1e2f3a4-b5c6-7890-abcd-ef1234567890"
    }
  ],
  "pagination": {
    "limit": 50,
    "offset": 0,
    "total": 1
  }
}
```

### GET `/operations/service-cases/:publicUuid`

**Permission:** `case.respond`.

**Response (200):**

```json
{
  "service_case": {
    "public_uuid": "sc000001-0000-4000-8000-000000000001",
    "case_code": "SC-MA4SJP2K-9C2E2EAA",
    "title": "Water leak in basement",
    "description": null,
    "priority_level": "medium",
    "status_code": "under_review",
    "category_code": "utilities",
    "intake_public_uuid": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
    "intake_report_code": "IR-MA4SJP2K-9C2E2EAA",
    "created_at": "2026-05-06T10:00:00.000Z",
    "updated_at": "2026-05-06T12:00:00.000Z",
    "last_updated": "2026-05-06T12:00:00.000Z",
    "location": {
      "public_uuid": "c2a9f1b0-4d3e-4c1a-9f2b-8e7d6c5b4a30",
      "latitude": 23.81,
      "longitude": 90.41,
      "address_text": "House 12, Road 3",
      "place_name": null,
      "admin_area_id": 1,
      "source": "user_shared"
    }
  },
  "status_history": [
    {
      "id": "1",
      "status_code": "under_review",
      "changed_at": "2026-05-06T10:00:00.000Z",
      "note": "Created from intake …",
      "changed_by": null
    }
  ],
  "messages": [],
  "assignments": [],
  "resolution": null
}
```

**Response (404):** `SERVICE_CASE_NOT_FOUND`.

For status history, assignments, and resolution without re-fetching the full payload, use case detail above. For **messages only**, use **GET `/operations/service-cases/:publicUuid/messages`**.

### GET `/operations/service-cases/:publicUuid/messages`

**Permission:** `case.respond`.

**Behavior:** Returns the message thread for the service case, oldest first. Includes **all** messages (including `is_internal = TRUE` when present). Each item includes `is_internal`.

**Response (200):**

```json
{
  "public_uuid": "…",
  "case_code": "SC-…",
  "messages": [
    {
      "id": "1",
      "message_type": "admin_reply",
      "subject": "…",
      "body": "…",
      "is_internal": false,
      "created_at": "2026-05-19T14:00:00.000Z",
      "sender": { "public_uuid": "…", "full_name": "…" }
    }
  ]
}
```

**Response (404):** `SERVICE_CASE_NOT_FOUND`.

### PATCH `/operations/service-cases/:publicUuid/status`

**Permission:** `case.respond`.

**Body:**

```json
{
  "statusCode": "under_review",
  "note": "Optional note, max 500 chars"
}
```

**Transitions (non-terminal →):**

New service cases are created in **`under_review`** (intake classification). The `submitted` transition remains for legacy rows.

- `submitted` → `under_review` \| `cancelled`
- `under_review` → `awaiting_user_response` \| `closed` \| `cancelled`
- `awaiting_user_response` → `under_review` \| `closed` \| `cancelled`

`resolved` is **not** set here; use **POST `/resolve`**. `escalated_to_emergency` is set only via **POST `/intake/reports/:reportPublicUuid/escalate`**.

Terminal cases cannot change status (`409` `INVALID_STATUS_TRANSITION`).

**Response (200):** same full detail shape as **GET `/operations/service-cases/:publicUuid`**, plus:

```json
{
  "message": "Service case status updated",
  "service_case": { "status_code": "awaiting_user_response" }
}
```

### POST `/operations/service-cases/:publicUuid/messages`

**Permission:** `case.respond`.

**Body:**

```json
{
  "title": "We need more information",
  "description": "Please send a photo of the leak"
}
```

**Response (201):**

```json
{
  "message": "Dispatcher response recorded",
  "case_message": {
    "id": "16",
    "message_type": "admin_reply",
    "subject": "We need more information",
    "body": "Please send a photo of the leak",
    "created_at": "2026-05-19T16:00:00.000Z"
  }
}
```

**Errors:** `409` `SERVICE_CASE_NOT_UPDATABLE` on terminal cases; `422` `VALIDATION_ERROR` for invalid body or param.

### POST `/operations/service-cases/:publicUuid/assignments`

**Permission:** `case.assign`.

**Body:**

```json
{
  "assignedToUserPublicUuid": "d1e2f3a4-b5c6-7890-abcd-ef1234567890",
  "note": "Primary handler for utilities"
}
```

Ends any active assignment on the case, then inserts a new **active** row.

**Response (201):**

```json
{
  "message": "Service case assigned",
  "assignment": {
    "id": "3",
    "assigned_to_user_public_uuid": "d1e2f3a4-b5c6-7890-abcd-ef1234567890",
    "assignment_status": "active"
  }
}
```

**Errors:** `404` `ASSIGNEE_USER_NOT_FOUND`.

### POST `/operations/service-cases/:publicUuid/resolve`

**Permission:** `case.respond`.

**Body:**

```json
{
  "resolutionType": "advice_given",
  "resolutionText": "Required narrative",
  "recommendedFacilityId": 1 //has to be a valid facility id
}
```

`resolutionType`: `advice_given` \| `referred_to_facility` \| `escalated` \| `no_action_needed` \| `duplicate`. `recommendedFacilityId` optional; must reference an existing `facilities.id` when provided.

Inserts `case_resolutions` then status history to **`resolved`** (trigger syncs `current_status_id`).

**Response (201):** full detail payload same as **GET `/operations/service-cases/:publicUuid`**, with `resolution` populated:

```json
{
  "message": "Service case resolved",
  "service_case": { "status_code": "resolved" },
  "resolution": {
    "id": "1",
    "resolution_type": "advice_given",
    "resolution_text": "Advised citizen to shut off main valve",
    "recommended_facility_id": null,
    "resolved_at": "2026-05-20T10:00:00.000Z",
    "resolved_by": {
      "public_uuid": "d1e2f3a4-b5c6-7890-abcd-ef1234567890",
      "full_name": "Dispatcher One"
    }
  }
}
```

**Errors:** `409` `CASE_ALREADY_RESOLVED` (terminal or duplicate resolution), `422` `FACILITY_NOT_FOUND`.

---

## Admin — agencies and representatives

All routes require JWT and permission **`agency.manage`** (`system_admin` receives this on bootstrap).

Assigning role **`agency_representative`** via `POST /users/:userId/roles` is **blocked** (`403` `ROLE_ASSIGNMENT_NOT_ALLOWED`). Use onboard or representatives routes instead.

### POST `/admin/agencies/onboard`

Single transaction: create a new agency **or** use an existing one. When **`user_public_uuid`** is provided, link that **existing** user, upsert **`agency_memberships`** (`representative`, `active`), and assign **`agency_representative`** if missing. When omitted, only the agency is created or resolved (no membership or role changes).

**Body (new agency, with representative):**

```json
{
  "user_public_uuid": "<user public uuid>",
  "agency": {
    "agency_code": "DHK-FIRE-02",
    "name": "Dhaka Fire Service North",
    "agency_type_code": "fire_service",
    "description": "optional",
    "head_office_location": {
      "latitude": 23.81,
      "longitude": 90.41,
      "source": "manual_entry"
    }
  }
}
```

**Body (new agency, agency only):** omit `user_public_uuid`.

```json
{
  "agency": {
    "agency_code": "DHK-FIRE-02",
    "name": "Dhaka Fire Service North",
    "agency_type_code": "fire_service",
    "description": "optional",
    "head_office_location": {
      "latitude": 23.81,
      "longitude": 90.41,
      "source": "manual_entry"
    }
  }
}
```

**Body (existing agency, with representative):**

```json
{
  "user_public_uuid": "<user public uuid>",
  "agency_public_uuid": "b2000001-0000-4000-8000-000000000001"
}
```

**Body (existing agency, agency only):** omit `user_public_uuid`.

```json
{
  "agency_public_uuid": "b2000001-0000-4000-8000-000000000001"
}
```

**Response (201, with representative):**

```json
{
  "message": "Agency representative onboarded",
  "agency": {
    "public_uuid": "b2000001-0000-4000-8000-000000000010",
    "agency_code": "DHK-FIRE-02",
    "name": "Dhaka Fire Service North",
    "agency_type_code": "fire_service",
    "description": null,
    "is_active": true,
    "created_at": "2026-05-20T10:00:00.000Z",
    "updated_at": "2026-05-20T10:00:00.000Z"
  },
  "membership_public_uuid": "d4000001-0000-4000-8000-000000000099",
  "user_public_uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

**Response (201, agency only):** `"message": "Agency onboarded"`, same `agency` object; `membership_public_uuid` and `user_public_uuid` are omitted.

**Errors:** `404` `USER_NOT_FOUND` (when `user_public_uuid` is sent), `404` `AGENCY_NOT_FOUND`, `409` `AGENCY_CODE_CONFLICT`, `409` `USER_ALREADY_REPRESENTATIVE` (when linking a representative).

### GET `/admin/agencies`

Query: `limit` (1–100, default 20), `offset` (default 0). Optional distance sort: any one of `nearIncidentPublicUuid`, `nearIntakeReportPublicUuid`, `nearServiceCasePublicUuid`, `nearDisasterAffectedAreaPublicUuid`, `nearFacilityPublicUuid`, plus `sort=distance_asc` and optional `includeDistance=true`.

**Response (200):**

```json
{
  "total": 3,
  "limit": 20,
  "offset": 0,
  "agencies": [
    {
      "public_uuid": "b2000001-0000-4000-8000-000000000001",
      "agency_code": "DHK-FIRE-01",
      "name": "Dhaka Fire Service",
      "agency_type_code": "fire_service",
      "description": "City fire response",
      "is_active": true,
      "created_at": "2026-05-01T00:00:00.000Z",
      "updated_at": "2026-05-01T00:00:00.000Z"
    }
  ]
}
```

### GET `/admin/agencies/:agencyPublicUuid`

**Response (200):**

```json
{
  "agency": {
    "public_uuid": "b2000001-0000-4000-8000-000000000001",
    "agency_code": "DHK-FIRE-01",
    "name": "Dhaka Fire Service",
    "agency_type_code": "fire_service",
    "description": "City fire response",
    "is_active": true,
    "created_at": "2026-05-01T00:00:00.000Z",
    "updated_at": "2026-05-01T00:00:00.000Z"
  },
  "representatives": [
    {
      "public_uuid": "d4000001-0000-4000-8000-000000000001",
      "user_public_uuid": "f1e2d3c4-b5a6-7890-abcd-ef1234567890",
      "full_name": "Fire Rep",
      "email": "fire.rep@niers.test",
      "membership_role": "representative",
      "membership_status": "active",
      "joined_at": "2026-05-01T00:00:00.000Z",
      "left_at": null
    }
  ],
  "units": [
    {
      "public_uuid": "c3000001-0000-4000-8000-000000000001",
      "unit_code": "FIRE-01",
      "unit_name": "Fire Engine Alpha",
      "unit_type_code": "fire_truck",
      "status_code": "available",
      "is_active": true
    }
  ],
  "contacts": []
}
```

### PATCH `/admin/agencies/:agencyPublicUuid`

Metadata only (`agency_code`, `name`, `description`, optional `head_office_location`). Use deactivate route for `is_active`.

**Body:**

```json
{
  "name": "Dhaka Fire Service (Central)",
  "description": "Updated description"
}
```

**Response (200):**

```json
{
  "agency": {
    "public_uuid": "b2000001-0000-4000-8000-000000000001",
    "agency_code": "DHK-FIRE-01",
    "name": "Dhaka Fire Service (Central)",
    "agency_type_code": "fire_service",
    "description": "Updated description",
    "is_active": true,
    "created_at": "2026-05-01T00:00:00.000Z",
    "updated_at": "2026-05-20T11:00:00.000Z"
  }
}
```

### PATCH `/admin/agencies/:agencyPublicUuid/deactivate`

Sets `is_active = false` (no hard delete). In the same transaction, deactivates all **active representative** memberships for the agency (`membership_status = inactive`, `left_at = NOW()`). Removes `agency_representative` from `user_roles` per affected user when they have no remaining **active** representative memberships elsewhere. Use activate route to restore agency and representative access, or re-link via `POST /admin/agencies/:agencyPublicUuid/representatives` / onboard.

**Response (200):** same shape as **GET `/admin/agencies/:agencyPublicUuid`** (full `agency`, `representatives`, `units`, `contacts`), plus:

```json
{
  "message": "Agency deactivated"
}
```

### PATCH `/admin/agencies/:agencyPublicUuid/activate`

Sets `is_active = true`. In the same transaction, reactivates all **inactive representative** memberships for the agency (`membership_status = active`, `left_at = NULL`). Restores `agency_representative` in `user_roles` per affected user. Fails with `409` `USER_ALREADY_REPRESENTATIVE` if any user would have active representative memberships at two agencies.

**Response (200):** same shape as **GET `/admin/agencies/:agencyPublicUuid`**, plus `"message": "Agency activated"`.

**Errors:** `404` `AGENCY_NOT_FOUND`, `409` `USER_ALREADY_REPRESENTATIVE`.

### POST `/admin/agencies/:agencyPublicUuid/representatives`

**Body:**

```json
{
  "user_public_uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
}
```

**Response (201):**

```json
{
  "message": "Agency representative linked",
  "representative": {
    "public_uuid": "d4000001-0000-4000-8000-000000000002",
    "user_public_uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "membership_role": "representative",
    "membership_status": "active",
    "joined_at": "2026-05-20T12:00:00.000Z"
  }
}
```

### GET `/admin/agencies/:agencyPublicUuid/representatives`

**Response (200):**

```json
{
  "agency_public_uuid": "b2000001-0000-4000-8000-000000000001",
  "representatives": [
    {
      "public_uuid": "d4000001-0000-4000-8000-000000000001",
      "user_public_uuid": "f1e2d3c4-b5a6-7890-abcd-ef1234567890",
      "full_name": "Fire Rep",
      "email": "fire.rep@niers.test",
      "membership_role": "representative",
      "membership_status": "active",
      "joined_at": "2026-05-01T00:00:00.000Z",
      "left_at": null
    }
  ]
}
```

### PATCH `/admin/agency-memberships/:membershipPublicUuid/deactivate`

Sets `membership_status = inactive`, `left_at = NOW()`. In the same transaction, removes `agency_representative` from `user_roles` when the user has no remaining **active** representative memberships (`membership_role = representative`, `membership_status = active`). Re-link via `POST /admin/agencies/:agencyPublicUuid/representatives` or onboard restores the role.

**Response (200):**

```json
{
  "message": "Agency membership deactivated",
  "membership": {
    "public_uuid": "d4000001-0000-4000-8000-000000000001",
    "membership_status": "inactive",
    "left_at": "2026-05-20T13:00:00.000Z"
  }
}
```

**Errors:** `404` `MEMBERSHIP_NOT_FOUND`, `409` `MEMBERSHIP_ALREADY_INACTIVE`.

---

## Agency representative

All routes require JWT, the listed permission, and an **active** `agency_memberships` row with `membership_role = representative` for the caller. Otherwise **`403` `MEMBERSHIP_INACTIVE`**.

Ownership: dispatches/units via `emergency_units.agency_id`; incidents via `incident_agency_participation`; response logs require agency participation on the incident.

### Demo stable UUIDs

| Resource | UUID |
| --- | --- |
| Dhaka Fire Service | `b2000001-0000-4000-8000-000000000001` |
| Dhaka Police | `b2000001-0000-4000-8000-000000000002` |
| Dhaka Medical | `b2000001-0000-4000-8000-000000000003` |
| Fire rep membership | `d4000001-0000-4000-8000-000000000001` |
| Demo incident | `e5000001-0000-4000-8000-000000000001` |
| Fire demo dispatch | `f5000001-0000-4000-8000-000000000001` |

Demo users (bootstrap when `DEMO_REP_PASSWORD` is set): `fire.rep@niers.test`, `police.rep@niers.test`, `medical.rep@niers.test`. Demo dispatcher (`DEMO_DISPATCHER_PASSWORD`): `dispatcher@niers.test`.

### GET `/agency/me`

**Response (200):**

```json
{
  "agency": {
    "public_uuid": "b2000001-0000-4000-8000-000000000001",
    "agency_code": "DHK-FIRE-01",
    "name": "Dhaka Fire Service",
    "description": "City fire response",
    "agency_type_code": "fire_service",
    "is_active": true
  },
  "membership": {
    "public_uuid": "d4000001-0000-4000-8000-000000000001",
    "membership_role": "representative",
    "membership_status": "active",
    "joined_at": "2026-05-01T00:00:00.000Z"
  },
  "counts": {
    "total_units": 3,
    "active_units": 3,
    "open_dispatches": 1,
    "active_incidents": 1
  }
}
```

### GET `/agency/incidents`

Minimal list for own agency participation. Query: `limit`, `offset`.

**Response (200):**

```json
{
  "limit": 20,
  "offset": 0,
  "incidents": [
    {
      "incident_public_uuid": "e5000001-0000-4000-8000-000000000001",
      "incident_code": "EI-DEMO0001",
      "status_code": "classified",
      "participation_status": "active"
    }
  ]
}
```

### GET `/agency/dispatches`

Dispatches for units owned by the agency; each item includes nested `incident` and `unit` summaries.

**Response (200):**

```json
{
  "limit": 20,
  "offset": 0,
  "dispatches": [
    {
      "public_uuid": "f5000001-0000-4000-8000-000000000001",
      "status_code": "assigned",
      "priority_level": "high",
      "assigned_at": "2026-05-19T10:05:00.000Z",
      "dispatched_at": null,
      "arrived_at": null,
      "completed_at": null,
      "cancelled_at": null,
      "incident": {
        "public_uuid": "e5000001-0000-4000-8000-000000000001",
        "incident_code": "EI-DEMO0001",
        "title": "Power line down"
      },
      "unit": {
        "public_uuid": "c3000001-0000-4000-8000-000000000001",
        "unit_code": "FIRE-01",
        "unit_name": "Fire Engine Alpha"
      }
    }
  ]
}
```

### PATCH `/agency/dispatches/:dispatchPublicUuid/status`

**Body:**

```json
{
  "statusCode": "dispatched",
  "note": "En route"
}
```

Same transitions as operations dispatch PATCH. Cross-agency UUID → **`404` `DISPATCH_NOT_FOUND`**.

**Response (200):**

```json
{
  "dispatch": {
    "public_uuid": "f5000001-0000-4000-8000-000000000001",
    "status_code": "dispatched",
    "dispatched_at": "2026-05-19T10:10:00.000Z"
  }
}
```

### GET `/agency/units` · POST `/agency/units` · PATCH `/agency/units/:unitPublicUuid`

**Example POST body:**
```json
{
  "unit_code": "FIRE-TRK-01",
  "unit_name": "Fire Truck Alpha",
  "unit_type_code": "fire_truck",
  "base_location": {
    "latitude": 23.8103,
    "longitude": 90.4125
  }
}
```
Creates unit and initial `unit_status_history` → `available`.

**PATCH:** metadata only (`unit_code`, `unit_name`, `base_location`).

**Response (201) for POST:**

```json
{
  "unit": {
    "public_uuid": "c3000001-0000-4000-8000-000000000099",
    "unit_code": "FIRE-TRK-01",
    "unit_name": "Fire Truck Alpha",
    "unit_type_code": "fire_truck",
    "status_code": "available",
    "is_active": true
  }
}
```

**Response (200) for PATCH:** `{ "unit": { …same fields… } }`.

**Example PATCH body:**
```json
{
  "unit_code": "FIRE-TRK-01",
  "unit_name": "Fire Truck Beta",
  "base_location": {
    "latitude": 23.8103,
    "longitude": 90.4125
  }
}
```

### GET `/agency/units`

**Response (200):**

```json
{
  "limit": 20,
  "offset": 0,
  "units": [
    {
      "public_uuid": "c3000001-0000-4000-8000-000000000001",
      "unit_code": "FIRE-01",
      "unit_name": "Fire Engine Alpha",
      "unit_type_code": "fire_truck",
      "status_code": "available",
      "is_active": true
    }
  ]
}
```

### PATCH `/agency/units/:unitPublicUuid/deactivate`

`is_active = false` if no dispatch in `assigned|dispatched|arrived`. **`409` `UNIT_HAS_ACTIVE_DISPATCH`**.

**Response (200):**

```json
{
  "message": "Unit deactivated",
  "unit": {
    "public_uuid": "c3000001-0000-4000-8000-000000000099",
    "is_active": false
  }
}
```

### PATCH `/agency/units/:unitPublicUuid/status`

**Body:**

```json
{
  "status_code": "busy",
  "note": "Supporting nearby incident"
}
```

Representatives may only toggle **available ↔ busy**.

**Response (200):**

```json
{
  "unit": {
    "public_uuid": "c3000001-0000-4000-8000-000000000001",
    "status_code": "busy"
  }
}
```

### GET `/agency/incidents/:incidentPublicUuid/notes`

Lists operator notes on an incident the caller’s agency participates in (`participation_status` `requested` or `active`). Same payload shape as operations GET notes. Query: `limit` (1–100, default 20), `offset` (default 0).

**Response (404):** `INCIDENT_NOT_IN_AGENCY`

### GET `/agency/incidents/:incidentPublicUuid/response-logs`

Lists **this agency’s** response logs on the incident (newest first). Query: `limit` (1–100, default 20), `offset` (default 0).

**Response (200):**

```json
{
  "incident_public_uuid": "e5000001-0000-4000-8000-000000000001",
  "limit": 20,
  "offset": 0,
  "response_logs": [
    {
      "id": 1,
      "log_type": "update",
      "message": "On scene, smoke visible on floor 3",
      "logged_at": "2026-05-19T10:15:00.000Z",
      "dispatch_public_uuid": "f5000001-0000-4000-8000-000000000001"
    }
  ]
}
```

**Errors:** `404` `INCIDENT_NOT_IN_AGENCY`.

### POST `/agency/incidents/:incidentPublicUuid/response-logs`

**Body:**

```json
{
  "log_type": "update",
  "message": "On scene, smoke visible on floor 3",
  "dispatch_public_uuid": "optional"
}
```

**Response (201):**

```json
{
  "response_log": {
    "id": 2,
    "log_type": "update",
    "message": "On scene, smoke visible on floor 3",
    "logged_at": "2026-05-19T10:20:00.000Z",
    "dispatch_public_uuid": "f5000001-0000-4000-8000-000000000001"
  }
}
```

**Errors:** `404` `INCIDENT_NOT_IN_AGENCY`, `422` `RESPONSE_LOG_DISPATCH_MISMATCH`.

---

## Public disasters

No auth required.

### GET `/public/disasters`

Lists disasters in `declared`, `resolved`, or `closed` status (safe summary fields only).

**Response (200):**

```json
{
  "disasters": [
    {
      "disaster_public_uuid": "de000001-0000-4000-8000-000000000001",
      "event_code": "FLD-KUR-2026-01",
      "title": "Kurigram flood response",
      "disaster_type_code": "flood",
      "disaster_type_name": "Flood",
      "severity_level": "high",
      "disaster_status": "declared",
      "public_guidance": "Avoid low-lying roads; use designated shelters.",
      "started_at": "2026-06-01T06:00:00.000Z",
      "ended_at": null
    }
  ]
}
```

### GET `/public/disasters/:disasterPublicUuid`

Public summary: title, type, severity, status, guidance, dates, affected upazilas, shelter capacity rollup.

**Response (200):**

```json
{
  "disaster": {
    "disaster_public_uuid": "de000001-0000-4000-8000-000000000001",
    "event_code": "FLD-KUR-2026-01",
    "title": "Kurigram flood response",
    "disaster_type_code": "flood",
    "disaster_type_name": "Flood",
    "severity_level": "high",
    "disaster_status": "declared",
    "public_guidance": "Avoid low-lying roads; use designated shelters.",
    "started_at": "2026-06-01T06:00:00.000Z",
    "ended_at": null,
    "affected_upazilas": [
      {
        "upazila_name": "Kurigram Sadar",
        "district_name": "Kurigram"
      }
    ],
    "active_shelter_count": 2,
    "total_available_shelter_capacity": 450
  }
}
```

**Response (404):** `DISASTER_NOT_PUBLIC` for `monitoring` or `cancelled`.

---

## Reference data

### GET `/reference/administrative-areas/search`

**Auth:** dispatcher or system_admin disaster permissions.

**Query:** `areaType=district|upazila`, `q` (prefix), optional `limit`.

**Response (200):**

```json
{
  "areas": [
    {
      "id": 101,
      "code": "KUR-SADAR",
      "name": "Kurigram Sadar",
      "areaType": "upazila",
      "hierarchyPath": "Kurigram Sadar, Kurigram, Rangpur"
    }
  ]
}
```

---

## Operations — disasters

Base path: `/operations/disasters`. External IDs use `publicUuid` fields.

| Method | Path | Permission |
|--------|------|------------|
| POST | `/operations/disasters` | `disaster.create` |
| GET | `/operations/disasters` | `disaster.read` |
| GET | `/operations/disasters/:disasterPublicUuid` | `disaster.read` (internal dashboard) |
| POST | `/operations/disasters/:disasterPublicUuid/status` | `disaster.update_status` (`resolved`, `closed`, `cancelled`) |
| POST | `.../affected-areas` | `disaster.manage_affected_areas` |
| PATCH | `.../affected-areas/:affectedAreaPublicUuid` | `disaster.manage_affected_areas` |
| POST | `.../responsibilities` | `disaster.manage_responsibilities` |
| POST | `.../declarations/initial` | `disaster.declare` → status `declared`, auto shelter/hub activation |
| POST | `.../declarations/amendments` | `disaster.declare` |
| GET/POST/DELETE | `.../incidents` | `disaster.link_incidents` |
| POST | `.../shelters`, `.../relief-hubs` | `shelter.manage` |
| POST | `.../relief-requests`, distributions | `relief.*` |

### POST `/operations/disasters`

**Body:**

```json
{
  "eventTypeCode": "flood",
  "title": "Kurigram monsoon flooding",
  "severityLevel": "high"
}
```

**Response (201):**

```json
{
  "disaster": {
    "public_uuid": "de000001-0000-4000-8000-000000000001",
    "event_code": "DST-MA4SJP2K",
    "title": "Kurigram monsoon flooding",
    "description": null,
    "public_guidance": null,
    "severity_level": "high",
    "status_code": "monitoring",
    "event_type_code": "flood",
    "event_type_name": "Flood",
    "started_at": "2026-06-01T06:00:00.000Z",
    "ended_at": null,
    "created_at": "2026-06-01T06:00:01.000Z",
    "updated_at": "2026-06-01T06:00:01.000Z"
  }
}
```

### POST `/operations/disasters/:disasterPublicUuid/affected-areas`

**Body:**

```json
{
  "upazilaAdminAreaIds": [101, 102],
  "assessment": {
    "populationAffected": 12000,
    "notes": "River level above danger mark"
  }
}
```

Alternatively pass `districtAdminAreaId` to expand to all upazilas under the district (only upazila rows are stored).

**Response (201):** full **dashboard** payload (same as GET detail below), including newly added `affected_areas`.

### GET `/operations/disasters`

**Response (200):**

```json
{
  "disasters": [
    {
      "public_uuid": "de000001-0000-4000-8000-000000000001",
      "event_code": "DST-MA4SJP2K",
      "title": "Kurigram monsoon flooding",
      "status_code": "monitoring",
      "severity_level": "high",
      "event_type_code": "flood"
    }
  ]
}
```

### GET `/operations/disasters/:disasterPublicUuid`

Optional query: `sort=distance_asc`, `nearDisasterAffectedAreaPublicUuid`, `includeDistance=true` — re-sorts **`linked_incidents`**, **`shelters`**, and **`relief_hubs`** by distance from the affected upazila anchor; other dashboard sections keep default ordering.

**Response (200):** internal dashboard (abbreviated):

```json
{
  "disaster": {
    "public_uuid": "de000001-0000-4000-8000-000000000001",
    "event_code": "DST-MA4SJP2K",
    "title": "Kurigram monsoon flooding",
    "status_code": "declared",
    "severity_level": "high"
  },
  "status_history": [],
  "declarations": [],
  "affected_areas": [
    {
      "affected_area_public_uuid": "daa00001-0000-4000-8000-000000000001",
      "upazila_name": "Kurigram Sadar",
      "district_name": "Kurigram",
      "impact_level": "severe"
    }
  ],
  "responsibilities": [],
  "linked_incidents": [],
  "shelters": [],
  "relief_hubs": [],
  "relief_requests": [],
  "recent_audit_logs": []
}
```

Each **`shelters[]`** row is a shelter activation for this disaster (from `vw_disaster_shelter_capacity`). Key fields include `shelter_activation_public_uuid`, `facility_name`, `activation_status` (`active` | `finalized`, etc.), and capacity/occupancy metrics. UIs that create relief requests (POST `.../relief-requests`) must only offer rows with `activation_status === "active"`; the API returns `409` `SHELTER_NOT_ACTIVE` otherwise.

### POST `/operations/disasters/:disasterPublicUuid/status`

**Body:**

```json
{
  "statusCode": "resolved",
  "note": "Water receding; demobilizing shelters"
}
```

`statusCode`: `resolved` \| `closed` \| `cancelled`.

**Response (200):**

```json
{
  "disaster": {
    "public_uuid": "de000001-0000-4000-8000-000000000001",
    "status_code": "resolved",
    "ended_at": "2026-06-10T18:00:00.000Z"
  }
}
```

### POST `/operations/disasters/:disasterPublicUuid/declarations/initial`

**Body:**

```json
{
  "title": "Flood emergency declared — Kurigram",
  "publicGuidance": "Evacuate low-lying areas; use designated shelters.",
  "legalReference": "DM Act section …",
  "reason": "River above danger level"
}
```

**Response (201):** full dashboard payload (GET detail shape); disaster `status_code` becomes `declared` and shelter/hub auto-activation may run.

### PATCH `/operations/disasters/:disasterPublicUuid/affected-areas/:affectedAreaPublicUuid`

**Body:** assessment fields (`impactLevel`, `estimatedAffectedPeople`, `shelterSupportRequired`, `reliefSupportRequired`, `assessmentNote`).

**Response (200):** full dashboard payload (GET detail shape).

### POST `/operations/disasters/:disasterPublicUuid/responsibilities`

**Body:**

```json
{
  "agencyPublicUuid": "b3000001-0000-4000-8000-000000000001",
  "responsibilityType": "coordination",
  "isLead": true
}
```

**Response (201):** dashboard payload.

### POST `/operations/disasters/:disasterPublicUuid/shelters`

Manual activation of a shelter facility for the disaster.

**Body:**

```json
{
  "facilityPublicUuid": "f6000001-0000-4000-8000-000000000001",
  "usableCapacityOverride": 500,
  "manualOverrideNote": "Required when facility is outside affected/nearby areas"
}
```

| Field | Required | Notes |
|-------|----------|--------|
| `facilityPublicUuid` | yes | Registry facility with shelter capability |
| `usableCapacityOverride` | no | Positive integer; overrides default usable capacity for this activation |
| `manualOverrideNote` | conditional | Required (non-empty, max 1000) when the facility is **not** in an affected upazila or the same district as an affected upazila; otherwise omitted |

**Errors:** `422` `MANUAL_ACTIVATION_NOTE_REQUIRED` if override note missing when required; `409` `SHELTER_ALREADY_ACTIVATED` if an **active** activation already exists for this facility; `422` `FACILITY_MISSING_CAPABILITY`.

If a prior activation for the same facility was **deactivated** (`activation_status` `finalized`), the same POST **reactivates** that row instead of inserting a duplicate.

**Response (201):** `{ "activation": { "public_uuid", "activation_status", "facility_public_uuid", … } }`.

### POST `/operations/disasters/:disasterPublicUuid/relief-hubs`

Manual activation of a relief hub facility for the disaster.

**Body:**

```json
{
  "facilityPublicUuid": "f6000001-0000-4000-8000-000000000005",
  "manualOverrideNote": "Required when facility is outside affected/nearby areas"
}
```

| Field | Required | Notes |
|-------|----------|--------|
| `facilityPublicUuid` | yes | Registry facility with relief hub capability |
| `manualOverrideNote` | conditional | Same nearby-area rule as shelter activation |

**Errors:** `422` `MANUAL_ACTIVATION_NOTE_REQUIRED`; `409` `RELIEF_HUB_ALREADY_ACTIVATED` if an **active** activation already exists; `422` `FACILITY_MISSING_CAPABILITY`.

Deactivated (`finalized`) hub activations are **reactivated** on a new POST for the same facility, same as shelters.

**Response (201):** `{ "activation": { "public_uuid", "activation_status", "facility_public_uuid", … } }`.

### POST `/operations/disasters/:disasterPublicUuid/incidents`

**Body:**

```json
{
  "incidentPublicUuid": "e5000001-0000-4000-8000-000000000001"
}
```

**Response (201):**

```json
{
  "link": [
    {
      "incident_public_uuid": "e5000001-0000-4000-8000-000000000001",
      "incident_code": "EI-DEMO0001",
      "title": "Power line down",
      "incident_status": "classified",
      "linked_at": "2026-06-02T09:00:00.000Z",
      "link_note": null,
      "location_admin_area_id": 1,
      "location_upazila_name": "Kurigram Sadar"
    }
  ]
}
```

**Affected areas:** `upazilaAdminAreaIds` and/or `districtAdminAreaId` (expands to all upazilas under district; only upazila rows stored). Optional `assessment` object on add.

**Demo accounts (Kurigram live demo, `DEMO_REP_PASSWORD`):**

| Email | Agency |
|-------|--------|
| `relief.rep@niers.test` | District Disaster Management & Relief Office (`b3000001-0000-4000-8000-000000000001`) |
| `shelter.rep@niers.test` | Red Crescent Response Unit (`b3000001-0000-4000-8000-000000000002`) |
| `fire.rep@niers.test` | Dhaka Fire (dispatch regression) |
| `police.rep@niers.test` / `medical.rep@niers.test` | Dhaka demo agencies |

Seeded Kurigram facilities (examples): `f6000001-0000-4000-8000-000000000001` (college shelter), `f6000001-0000-4000-8000-000000000005` (relief warehouse). Relief catalog: `rice`, `bottled_water`, `blanket`, `dry_food_packet`, `medicine_kit`, `hygiene_kit`.

**No disaster operational rows are seeded** — create disasters, areas, declarations, and activations live during demo.

---

## Admin — facilities

Base path: `/admin/facilities`. Requires `facility.manage`.

### POST `/admin/facilities`

**Body:**

```json
{
  "facilityCode": "SHELTER-KUR-01",
  "name": "Kurigram College Shelter",
  "facilityTypeCode": "shelter",
  "location": {
    "latitude": 25.805,
    "longitude": 89.636,
    "source": "manual_entry"
  }
}
```

**Response (201):**

```json
{
  "facility": {
    "id": 1,
    "publicUuid": "f6000001-0000-4000-8000-000000000001",
    "facilityCode": "SHELTER-KUR-01",
    "name": "Kurigram College Shelter",
    "facilityTypeCode": "shelter",
    "isActive": true,
    "location": {
      "publicUuid": "c2a9f1b0-4d3e-4c1a-9f2b-8e7d6c5b4a30",
      "adminAreaId": 101,
      "latitude": 25.805,
      "longitude": 89.636,
      "addressText": "Kurigram College, Kurigram"
    },
    "capabilities": [],
    "defaultCapacities": []
  }
}
```

### GET `/admin/facilities`

**Response (200):**

```json
{
  "facilities": [
    {
      "id": 1,
      "publicUuid": "f6000001-0000-4000-8000-000000000001",
      "facilityCode": "SHELTER-KUR-01",
      "name": "Kurigram College Shelter",
      "facilityTypeCode": "shelter",
      "isActive": true
    }
  ]
}
```

### GET `/admin/facilities/:facilityPublicUuid`

**Response (200):** same `facility` object shape as POST (includes `capabilities` and `defaultCapacities`).

### PUT `/admin/facilities/:facilityPublicUuid/capabilities`

**Body:** `{ "capabilityCodes": ["shelter_people", "relief_distribution"] }`

**Response (200):** `{ "facility": { … } }` with updated `capabilities`.

### PUT `/admin/facilities/:facilityPublicUuid/default-capacities`

**Body:**

```json
{
  "capacities": [
    { "capacityType": "shelter_people", "totalCapacity": 500 }
  ]
}
```

**Response (200):** `{ "facility": { … } }` with updated `defaultCapacities`.

### PATCH `/admin/facilities/:facilityPublicUuid/deactivate`

Deactivates the facility (`isActive: false`). Inactive facilities are excluded from disaster activation eligibility.

**Response (200):**

```json
{
  "message": "Facility deactivated",
  "facility": { "…": "same shape as GET detail" }
}
```

**Errors:** `404 FACILITY_NOT_FOUND`, `409 FACILITY_ALREADY_INACTIVE`.

### PATCH `/admin/facilities/:facilityPublicUuid/activate`

Activates the facility (`isActive: true`). Restores eligibility for disaster activation.

**Response (200):**

```json
{
  "message": "Facility activated",
  "facility": { "…": "same shape as GET detail" }
}
```

**Errors:** `404 FACILITY_NOT_FOUND`, `409 FACILITY_ALREADY_ACTIVE`.

---

## Development RBAC bootstrap

See [demo-accounts.md](./demo-accounts.md) for the full list of bootstrap emails, roles, and password env vars.

On server start, the backend seeds minimal RBAC and can bootstrap a dev **system_admin**. **Dispatcher** users receive `incident.*`, `dispatch.*`, and case permissions. **`agency_representative`** receives own-agency dispatch permissions plus `disaster.read`, `shelter.record_occupancy_own`, and `relief.request_own_shelter`. **`system_admin`** receives all bootstrap permissions including disaster, facility, shelter, and relief modules.

**Env vars:**

- `SYSTEM_ADMIN__EMAIL`
- `SYSTEM_ADMIN_PASSWORD`
- `SYSTEM_ADMIN_NAME`
- `SYSTEM_ADMIN_PHONE` (exactly 11 digits)
- `DEMO_REP_PASSWORD` (min 8 chars; creates demo reps when missing)
- `DEMO_DISPATCHER_PASSWORD` (min 8 chars; creates `dispatcher@niers.test` when missing)

If no active `system_admin` assignment exists and these are set, the app creates or finds the user and assigns **`system_admin`**.