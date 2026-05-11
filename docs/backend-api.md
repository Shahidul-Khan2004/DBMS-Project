# Backend API (Insomnia test guide)

Living reference for HTTP endpoints. Update this file whenever routes or contract-relevant validation change.

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
  "urgencyType": "non_emergency",
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

- `urgencyType`: `non_emergency` \| `emergency` \| `unknown` (optional; default `unknown`). Portal users **must not** send `emergency` unless they hold **`incident.classify`**; otherwise `403`. Use `unknown` / `non_emergency`; operators escalate via classify or promote flows.
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
    "urgency_type": "non_emergency",
    "reported_at": "2026-05-04T12:00:00.000Z"
  }
}
```

**Errors:** `422` `REPORT_CHANNEL_NOT_FOUND`, `REPORT_CATEGORY_NOT_FOUND`, `VALIDATION_ERROR`, `403` for disallowed `urgencyType`.

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
      "urgency_type": "non_emergency",
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

Queue of intake reports. Query: `intake_status`, `urgency_type`, `categoryCode`, `limit` (1–100, default 50), `offset`, `sort` (`reported_at_desc` \| `reported_at_asc`).

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
- `categoryCode`, `summary` (**required**); `description`, `urgencyType`, `reportedAt` optional
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

## Development RBAC bootstrap

On server start, the backend seeds minimal RBAC and can bootstrap a dev **system_admin**.

**Env vars:**

- `SYSTEM_ADMIN__EMAIL`
- `SYSTEM_ADMIN_PASSWORD`
- `SYSTEM_ADMIN_NAME`
- `SYSTEM_ADMIN_PHONE` (exactly 11 digits)

If no active `system_admin` assignment exists and these are set, the app creates or finds the user and assigns **`system_admin`**.
