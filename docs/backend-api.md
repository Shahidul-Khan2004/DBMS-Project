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

## Location payloads (intake, locations, operations)

Structured `location` objects use **`latitude`** and **`longitude`** (required numbers in validation).

- **`address_text`** — optional in the API schema. If omitted (preferred) or blank, the backend will derive and store a proper fallback from coordinates (see `locationAddressService`).
- **`place_name`** — optional.
- **`admin_area_id`** — optional positive integer; will be resolved from GPS when omitted (preferred).
- **`source`** — `user_shared` \| `dispatcher_selected` \| `api_geocoded` \| `manual_entry` (required on **`POST /locations`**; optional on intake / incident payloads where the schema allows it).

Do not send **`location`** and **`locationId`** in the same request.

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

**Response (201):** `message`, `accessToken`, `refreshToken`, `user` (see [User object](#user-object-user-in-auth-and-usersme)).

**Example error (409):** `EXISTING_EMAIL`.

### POST `/auth/login`

**Body:** `{ "email", "password" }`

**Response (200):** same token + `user` shape as register.

**Example error (401):** `INVALID_CREDENTIALS`.

### POST `/auth/refresh`

**Body:** `{ "refreshToken": "<JWT_REFRESH_TOKEN>" }`

**Response (200):** new access + refresh tokens and `user`.

**Example error (401):** `INVALID_REFRESH_TOKEN`.

---

## Users

### GET `/users/me`

Returns `{ "user": { ... } }` with the same `user` fields as auth responses.

**Example error (401):** `AUTH_HEADER_INVALID`.

### POST `/users/:userId/roles`

Assigns a role to another user by **target user public UUID**.

- **Permission:** `auth.manage_roles`
- **Body:** `{ "roleCode": "dispatcher" }` (normalized to lowercase)
- **Response (200):** `{ "message", "userId", "roleCode" }`
- **Errors:** `403` `FORBIDDEN`, `404` `ROLE_NOT_FOUND`, etc.

---

## Locations

Citizen-owned saved locations; `public_uuid` is used as **`locationId`** on intake.

### POST `/locations`

**Body:** structured location (see [Location payloads](#location-payloads-intake-locations-operations)); **`source`** is required.

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

**Response (200):** `{ "locations": [ … ] }` (same element shape as create).

### GET `/locations/:publicUuid`

**Access:** location owner, or caller with `incident.classify` / `incident.create`.

**Response (200):** `{ "location": { … } }`

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

- `location` / `locationId`: optional, mutually exclusive; follow [Location payloads](#location-payloads-intake-locations-operations).
- Plain string `location` is **not** accepted.
- If the report may later go down the emergency path, ensure a stored location (`reported_location_id`) via inline location or `locationId` before classify/promote.

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

**Response (200):** `{ "report": { … } }` including:

- Same core fields as list rows, plus
- **`location`**: structured object or `null` (`public_uuid`, `latitude`, `longitude`, `address_text`, `place_name`, `admin_area_id`, `source`)
- **`location_text`**: backward-compatible string (from stored address when present)

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

**Response (200):** `{ "message": "Reported location updated", "report": { … } }` (same shape as GET detail / list mapper as applicable).

### GET `/intake/reports/:reportPublicUuid/reported-location-history`

History ordered by **`changed_at` descending** (newest change first).

Each element includes:

- `change_kind`: `initial_create` \| `location_patch`
- `location`, `previous_location` (nullable)
- `changed_by`: `{ public_uuid, full_name, actor_kind }` where `actor_kind` is `dispatcher` (includes system-admin operators in current mapping) or `citizen`

**Response (200):** `{ "history": [ … ] }` (empty array when allowed but no history rows).

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

**Response (201):** `{ "message", "service_case", "intake" }` — DB-shaped rows.

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

**Response (201):** `{ "message", "emergency_call", "emergency_incident", "incident_report_link", "intake" }`.

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
      "status": "reported",
      "category": "infrastructure_emergency",
      "occurred_at": "2026-05-06T07:41:03.000Z",
      "age_minutes": 18
    }
  ]
}
```

### GET `/operations/intake-reports`

Queue of intake reports. Query: `intake_status`, `categoryCode`, `limit` (1–100, default 50), `offset`, `sort` (`reported_at_desc` \| `reported_at_asc`).

**Response (200):** `{ "intake_reports": [ … ], "pagination": { "limit", "offset", "total" } }`

### GET `/operations/intake-reports/:reportPublicUuid`

Single row, same shape as list elements.

**Response (404):** `INTAKE_REPORT_NOT_FOUND`

### GET `/operations/intake-reports/:reportPublicUuid/reported-location-history`

Same payload shape as the reporter **`GET /intake/reports/.../reported-location-history`**, for users with **`incident.classify`**.

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

**Response (201):** `{ "message", "incident" }` — `incident` matches detail map (codes, timestamps, etc.).

**Errors:** `422` `EMERGENCY_INCIDENT_REQUIRES_LOCATION`, `409` `INTAKE_NOT_PROMOTABLE`, `INTAKE_ALREADY_LINKED`, …

### POST `/operations/gateway/999/intake-and-incident`

Dispatcher quick flow: creates intake on **`emergency_call`** channel, ensures emergency call placeholder, then branches to **`service_case`** or **`emergency_incident`** per `disposition`.

**Body (validated):**

- `disposition`: `service_case` \| `emergency_incident` (**required**)
- `categoryCode`, `summary` (**required**); `description`, `reportedAt` optional
- Exactly one of **`location`** or **`locationId`** (**required**)
- `callerPhoneNumber`, `callStartedAt` optional call metadata
- `incidentTitle`, `incidentDescription` optional overrides
- If `disposition === "emergency_incident"`: **`severityCode`** required
- If `service_case`: **`priorityLevel`** optional (`low` \| `medium` \| `high` \| `urgent`)

**Response (201):** `{ "message": "999 intake and incident flow completed", … }` — spreads `intake`, branch-specific rows (`service_case` / emergency entities), and `emergency_call` as implemented in `createGateway999IntakeAndIncident`.

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

**Response (201):** `{ "message": "Incident created", "incident": { … } }`

**Errors:** `422` for `REPORT_CATEGORY_NOT_FOUND`, `LOCATION_REQUIRED`, `INCIDENT_TITLE_REQUIRED`, `EMERGENCY_INCIDENT_REQUIRES_LOCATION`, etc.

### GET `/operations/incidents`

Query: `status_code`, `reported_after`, `reported_before`, `limit`, `offset`. Ordered by `reported_at` descending.

**Response (200):** `{ "incidents": [ … ], "pagination": { … } }`

### GET `/operations/incidents/:incidentPublicUuid`

**Response (200):**

```json
{
  "incident": {},
  "linked_intake_reports": [
    {
      "link_type": "primary_report",
      "linked_at": "2026-05-04T12:05:00.000Z",
      "intake_public_uuid": "…",
      "intake_report_code": "IR-…",
      "intake_summary": "…",
      "intake_status": "linked_to_incident"
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
  ]
}
```

`incident` is the full detail DTO; timeline preview is capped (e.g. last 50 by `event_time`).

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

- `reported` → `classified`, `cancelled`
- `classified` → `in_progress`, `resolved`, `closed`, `cancelled`
- `in_progress` → `resolved`, `closed`, `cancelled`

Terminal statuses cannot change again.

When transitioning to **`resolved`**, **`closed`**, or **`cancelled`**, the server also (same transaction):

- Finalizes all non-terminal dispatches on the incident (`completed` for `resolved`/`closed`, `cancelled` for `cancelled`), advancing through valid dispatch transitions with note `Incident <statusCode>`.
- Sets every dispatched unit that is still **`busy`** back to **`available`** via `unit_status_history`.

**Response (200):** `{ "message": "Incident status updated", "incident": { … } }`

**Response (409):** `INVALID_STATUS_TRANSITION`

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

**Response (201):** `{ "message": "Operator note added", "note": { … } }`

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

**Response (201):** `{ "message": "Intake report linked to incident", "link": { … } }` (link row + incident/intake identifiers per repository).

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
    "is_lead_agency": false,
    "participation_status": "active",
    "joined_at": "2026-05-19T10:00:00.000Z"
  }
}
```

**Errors:** `404 INCIDENT_NOT_FOUND`, `404 AGENCY_NOT_FOUND`, `409 AGENCY_ALREADY_PARTICIPATING`

### GET `/operations/units/available`

**Permission:** `dispatch.create`.

**Query:** `incidentPublicUuid` (required UUID) — only units whose agency participates on the incident (`participation_status` `requested` or `active`) and `status_code` = `available`.

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

**Response (200):** `{ "message": "Dispatch status updated", "dispatch": { … } }`

**Errors:** `404 DISPATCH_NOT_FOUND`, `409 INVALID_STATUS_TRANSITION`, `422 INVALID_STATUS_CODE`

### GET `/operations/agencies/workload`

**Permission:** `dispatch.create` or `incident.assign_agency`.

Reads `vw_agency_workload` joined with agency `public_uuid`.

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

**Body:** `{ "title": "…", "description": "optional" }` — `title` required (trimmed, max 255); `description` optional. Stored in `case_messages` as `subject` + `body` (same as operations messages).

**Behavior (single DB transaction for case writes):** Inserts `case_messages` with `message_type` **`user_message`**. If the case’s current status is **`awaiting_user_response`**, the server also inserts **`case_status_history`** to **`under_review`** (allowed transition; trigger updates `service_cases.current_status_id`) and writes an **`audit_log`** row for the status change (`service_case.status_patch`, with `via: "citizen_message"` in details). Always writes **`service_case.message_posted`** audit for the new message.

**Notifications (best-effort, after commit):** If there is an **active** `case_assignments` row (`assignment_status = 'active'`, `ended_at IS NULL`), the server queues in-app + email delivery for the assignee with fallback copy **"Citizen replied to service case"** (same text as title and body when templates are missing). If there is no active assignee, no notification is sent. Notification failures do **not** roll back the message or status change.

**Response (201):** `{ "message": "Citizen reply recorded", "case_message": { "id", "message_type": "user_message", "subject", "body", "created_at" } }`.

**Errors:**

- `401` — missing/invalid `Authorization` bearer token.
- `403` `FORBIDDEN` — service case exists but the caller is not the reporter (`"You are not the reporter for this service case"`).
- `404` `SERVICE_CASE_NOT_FOUND` — unknown `publicUuid`.
- `409` `SERVICE_CASE_NOT_UPDATABLE` — terminal case (cannot add messages).
- `422` `VALIDATION_ERROR` — invalid body or invalid `publicUuid` param.

### POST `/intake/reports/:reportPublicUuid/escalate`

Promotes an intake that is already on the **service case** path (`intake_status` must be `linked_to_case`) to an **emergency incident**, with a linked `case_escalations` row and case status `escalated_to_emergency`. **Roles:** `dispatcher` or `system_admin`. **Permissions:** `case.escalate` **and** `incident.create`.

**Body:** (`severityCode`, optional `incidentTitle`, `incidentDescription`, `reportedAt`) **plus** required `escalationReason` (1–1000 chars).

**Location rule:** the incident’s primary `locations.id` is the **latest** row in `intake_report_location_history` for this intake (by `changed_at`), else `intake_reports.reported_location_id`, else `service_cases.current_location_id`. The same `locations` row is referenced in `incident_location_history` with `is_current = TRUE` (no geometry copy).

**Response (201):** `{ "message": "Service case escalated to emergency incident", "incident": { … }, "service_case": { … }, "intake_public_uuid": "…" }` — `incident` includes `public_uuid`, `incident_code`, `title`, `origin_type` (`service_case_escalation`).

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

**Response (200):** `{ "service_cases": [ … ], "pagination": { "limit", "offset", "total" } }`.

### GET `/operations/service-cases/:publicUuid`

**Permission:** `case.respond`.

**Response (200):** `{ "service_case": { … }, "status_history": [ … ], "messages": [ … ], "assignments": [ … ], "resolution": { … } \| null }` — `resolution` is absent or a single object when `case_resolutions` exists.

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

- `submitted` → `under_review` \| `cancelled`
- `under_review` → `awaiting_user_response` \| `closed` \| `cancelled`
- `awaiting_user_response` → `under_review` \| `closed` \| `cancelled`

`resolved` is **not** set here; use **POST `/resolve`**. `escalated_to_emergency` is set only via **POST `/intake/reports/:reportPublicUuid/escalate`**.

Terminal cases cannot change status (`409` `INVALID_STATUS_TRANSITION`).

**Response (200):** `{ "message": "Service case status updated", "service_case": { … }, "status_history": [ … ], "messages": [ … ], "assignments": [ … ], "resolution": … }`.

### POST `/operations/service-cases/:publicUuid/messages`

**Permission:** `case.respond`.

**Body:** `{ "title": "…", "description": "optional" }` — `title` required, max 255.

**Behavior (single DB transaction for case writes):** Inserts `case_messages` with `message_type` **`admin_reply`**. If the case’s current status is **`under_review`**, the server also inserts **`case_status_history`** to **`awaiting_user_response`** (trigger updates `service_cases.current_status_id`) and writes **`audit_log`** for that status change (`service_case.status_patch`, with `via: "dispatcher_message"` in details). Always writes **`service_case.message_posted`** for the new message.

**Notifications (best-effort, after commit):** When the case has a reporter user, the server queues in-app + email for the reporter with fallback copy **"Dispatcher replied to your service case"** (same text as title and body when templates are missing). Notification failures do **not** roll back the message or status change.

**Response (201):** `{ "message": "Dispatcher response recorded", "case_message": { "id", "message_type": "admin_reply", "subject", "body", "created_at" } }`.

**Errors:** `409` `SERVICE_CASE_NOT_UPDATABLE` on terminal cases; `422` `VALIDATION_ERROR` for invalid body or param.

### POST `/operations/service-cases/:publicUuid/assignments`

**Permission:** `case.assign`.

**Body:** `{ "assignedToUserPublicUuid": "<user public uuid>", "note": "optional max 500" }`.

Ends any active assignment on the case, then inserts a new **active** row (`assigned_admin_id` references `users.id` per schema).

**Response (201):** `{ "message": "Service case assigned", "assignment": { "id", "assigned_to_user_public_uuid", "assignment_status" } }`.

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

**Response (201):** `{ "message": "Service case resolved", …full detail payload same as GET… }`.

**Errors:** `409` `CASE_ALREADY_RESOLVED` (terminal or duplicate resolution), `422` `FACILITY_NOT_FOUND`.

---

## Admin — agencies and representatives

All routes require JWT and permission **`agency.manage`** (`system_admin` receives this on bootstrap).

Assigning role **`agency_representative`** via `POST /users/:userId/roles` is **blocked** (`403` `ROLE_ASSIGNMENT_NOT_ALLOWED`). Use onboard or representatives routes instead.

### POST `/admin/agencies/onboard`

Single transaction: link an **existing** user to an agency (create new agency **or** use existing), upsert **`agency_memberships`** (`representative`, `active`), assign **`agency_representative`** role if missing.

**Body (new agency):**

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

**Body (existing agency):**

```json
{
  "user_public_uuid": "<user public uuid>",
  "agency_public_uuid": "b2000001-0000-4000-8000-000000000001"
}
```

**Response (201):** `{ "message", "agency", "membership_public_uuid", "user_public_uuid" }`.

**Errors:** `404` `USER_NOT_FOUND`, `404` `AGENCY_NOT_FOUND`, `409` `AGENCY_CODE_CONFLICT`, `409` `USER_ALREADY_REPRESENTATIVE`.

### GET `/admin/agencies`

Query: `limit` (1–100, default 20), `offset` (default 0).

**Response (200):** `{ "total", "limit", "offset", "agencies": [{ "public_uuid", "agency_code", "name", "agency_type_code", "description", "is_active", "created_at", "updated_at" }] }`.

### GET `/admin/agencies/:agencyPublicUuid`

**Response (200):** `{ "agency", "representatives": [], "units": [], "contacts": [] }`.

### PATCH `/admin/agencies/:agencyPublicUuid`

Metadata only (`agency_code`, `name`, `description`, optional `head_office_location`). Use deactivate route for `is_active`.

### PATCH `/admin/agencies/:agencyPublicUuid/deactivate`

Sets `is_active = false` (no hard delete). In the same transaction, deactivates all **active representative** memberships for the agency (`membership_status = inactive`, `left_at = NOW()`). Removes `agency_representative` from `user_roles` per affected user when they have no remaining **active** representative memberships elsewhere. Use activate route to restore agency and representative access, or re-link via `POST /admin/agencies/:agencyPublicUuid/representatives` / onboard.

### PATCH `/admin/agencies/:agencyPublicUuid/activate`

Sets `is_active = true`. In the same transaction, reactivates all **inactive representative** memberships for the agency (`membership_status = active`, `left_at = NULL`). Restores `agency_representative` in `user_roles` per affected user. Fails with `409` `USER_ALREADY_REPRESENTATIVE` if any user would have active representative memberships at two agencies.

**Errors:** `404` `AGENCY_NOT_FOUND`, `409` `USER_ALREADY_REPRESENTATIVE`.

### POST `/admin/agencies/:agencyPublicUuid/representatives`

**Body:** `{ "user_public_uuid": "<uuid>" }` — same membership/role rules as onboard user leg.

### GET `/admin/agencies/:agencyPublicUuid/representatives`

**Response (200):** `{ "agency_public_uuid", "representatives": [{ "public_uuid", "user_public_uuid", "full_name", "email", "membership_role", "membership_status", "joined_at", "left_at" }] }`.

### PATCH `/admin/agency-memberships/:membershipPublicUuid/deactivate`

Sets `membership_status = inactive`, `left_at = NOW()`. In the same transaction, removes `agency_representative` from `user_roles` when the user has no remaining **active** representative memberships (`membership_role = representative`, `membership_status = active`). Re-link via `POST /admin/agencies/:agencyPublicUuid/representatives` or onboard restores the role.

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

Demo users (bootstrap when `DEMO_REP_PASSWORD` is set): `fire.rep@niers.test`, `police.rep@niers.test`, `medical.rep@niers.test`.

### GET `/agency/me`

**Response (200):**

```json
{
  "agency": { "public_uuid", "agency_code", "name", "description", "agency_type_code", "is_active" },
  "membership": { "public_uuid", "membership_role", "membership_status", "joined_at" },
  "counts": { "total_units", "active_units", "open_dispatches", "active_incidents" }
}
```

### GET `/agency/incidents`

Minimal list for own agency participation. Query: `limit`, `offset`.

### GET `/agency/dispatches`

Dispatches for units owned by the agency; each item includes nested `incident` and `unit` summaries.

### PATCH `/agency/dispatches/:dispatchPublicUuid/status`

Same body as operations dispatch PATCH: `{ "statusCode": "dispatched|arrived|completed|cancelled", "note": "optional" }`. Cross-agency UUID → **`404` `DISPATCH_NOT_FOUND`**.

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

### PATCH `/agency/units/:unitPublicUuid/deactivate`

`is_active = false` if no dispatch in `assigned|dispatched|arrived`. **`409` `UNIT_HAS_ACTIVE_DISPATCH`**.

### PATCH `/agency/units/:unitPublicUuid/status`

**Body:** `{ "status_code": "available|busy", "note": "optional" }` — representatives may only toggle **available ↔ busy**.

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

**Response (201):** `{ "response_log": { "id", "log_type", "message", "logged_at", "dispatch_public_uuid" } }`.

**Errors:** `404` `INCIDENT_NOT_IN_AGENCY`, `422` `RESPONSE_LOG_DISPATCH_MISMATCH`.

---

## Development RBAC bootstrap

On server start, the backend seeds minimal RBAC and can bootstrap a dev **system_admin**. **Dispatcher** users receive `incident.*`, `dispatch.*`, and case permissions. **`agency_representative`** receives only: `agency.view_own`, `agency.manage_own_units`, `dispatch.view_own_agency`, `dispatch.update_own_agency`, `response_log.create_own_agency`. **`system_admin`** receives all bootstrap permissions including **`agency.manage`** and the `*_own` set.

**Env vars:**

- `SYSTEM_ADMIN__EMAIL`
- `SYSTEM_ADMIN_PASSWORD`
- `SYSTEM_ADMIN_NAME`
- `SYSTEM_ADMIN_PHONE` (exactly 11 digits)
- `DEMO_REP_PASSWORD` (min 8 chars; creates demo reps when missing)

If no active `system_admin` assignment exists and these are set, the app creates or finds the user and assigns **`system_admin`**.