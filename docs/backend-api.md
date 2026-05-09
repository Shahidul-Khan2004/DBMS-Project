# Backend API (Insomnia Test Guide)

This is the living API doc for backend endpoints.  
Whenever a new endpoint is added, this file should be updated in the same change.

## Base URL

- Local: `http://localhost:8080`

## Common Headers

### Public endpoints

```http
Content-Type: application/json
```

### Protected endpoints

```http
Content-Type: application/json
Authorization: Bearer <ACCESS_TOKEN>
```

## Standard Error Shape

All API errors return this structure:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human readable message",
    "details": []
  }
}
```

`details` is optional and usually present for validation errors.

### User object (`user` in auth and `/users/me`)

- **`account_status`** comes from the `users.account_status` column (`active` \| `suspended` \| `disabled` \| `pending_verification`). This is the source of truth for lifecycle.
- **`is_active`** is not a database column. It is always `account_status === "active"` so clients can keep a simple boolean if they prefer.
- **`full_name`** and **`phone_number`** come from `user_profiles` (joined in the repository), not from `users`.

## Route index

- `GET /health`
- `POST /auth/register` · `POST /auth/login` · `POST /auth/refresh`
- `GET /users/me` · `POST /users/:userId/roles`
- `POST /intake/reports`
- `GET /intake/reports/my` · `GET /intake/reports/my/stats`
- `POST /intake/reports/:reportPublicUuid/classify/service-case`
- `POST /intake/reports/:reportPublicUuid/classify/emergency`
- `GET /operations/dispatcher/overview`
- `GET /operations/intake-reports`
- `GET /operations/intake-reports/:reportPublicUuid`
- `POST /operations/intake-reports/:reportPublicUuid/promote/emergency`
- `POST /operations/incidents` · `GET /operations/incidents`
- `GET /operations/incidents/:incidentPublicUuid`
- `PATCH /operations/incidents/:incidentPublicUuid/status`
- `POST /operations/incidents/:incidentPublicUuid/notes`

---

## 1) Health Check

### GET `/health`

Checks API + DB connectivity.

#### Headers

```http
Content-Type: application/json
```

#### Body

No request body.

#### Success Response (200)

```json
{
  "status": "RUNNING",
  "timestamp": "5/3/2026, 10:00:00 PM",
  "dbTime": "2026-05-03T16:00:00.000Z",
  "dbVersion": "8.0.36"
}
```

---

## 2) Register User

### POST `/auth/register`

Creates a new user and returns access and refresh tokens plus the public `user` object.

Registration inserts `users.account_status` as **`active`** so the account can log in and use tokens immediately. The SQL schema default for that column is `pending_verification`; the app overrides it on purpose for this MVP flow. To require email verification first, change the registration insert (and tests) to use `pending_verification` and add an activation path.

#### Headers

```http
Content-Type: application/json
```

#### Body

```json
{
  "email": "john@example.com",
  "fullName": "John Doe",
  "phoneNumber": "01700000000",
  "password": "StrongPass123",
  "rePassword": "StrongPass123"
}
```

- `phoneNumber` is required and must be 11 digits.

#### Success Response (201)

```json
{
  "message": "User registered successfully",
  "accessToken": "<JWT_ACCESS_TOKEN>",
  "refreshToken": "<JWT_REFRESH_TOKEN>",
  "user": {
    "id": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
    "email": "john@example.com",
    "full_name": "John Doe",
    "phone_number": "01700000000",
    "account_status": "active",
    "is_active": true,
    "created_at": "2026-05-03T16:00:00.000Z",
    "updated_at": "2026-05-03T16:00:00.000Z"
  }
}
```

#### Example Error (409)

```json
{
  "error": {
    "code": "EXISTING_EMAIL",
    "message": "Email already in use"
  }
}
```

---

## 3) Login User

### POST `/auth/login`

Authenticates user credentials and returns access and refresh tokens plus the public `user` object.

#### Headers

```http
Content-Type: application/json
```

#### Body

```json
{
  "email": "john@example.com",
  "password": "StrongPass123"
}
```

#### Success Response (200)

```json
{
  "message": "Login successful",
  "accessToken": "<JWT_ACCESS_TOKEN>",
  "refreshToken": "<JWT_REFRESH_TOKEN>",
  "user": {
    "id": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
    "email": "john@example.com",
    "full_name": "John Doe",
    "phone_number": "01700000000",
    "account_status": "active",
    "is_active": true,
    "created_at": "2026-05-03T16:00:00.000Z",
    "updated_at": "2026-05-03T16:00:00.000Z"
  }
}
```

#### Example Error (401)

```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password"
  }
}
```

---

## 4) Refresh Token

### POST `/auth/refresh`

Validates refresh token and returns a new access + refresh token pair.

#### Headers

```http
Content-Type: application/json
```

#### Body

```json
{
  "refreshToken": "<JWT_REFRESH_TOKEN>"
}
```

#### Success Response (200)

```json
{
  "message": "Token refreshed successfully",
  "accessToken": "<NEW_JWT_ACCESS_TOKEN>",
  "refreshToken": "<NEW_JWT_REFRESH_TOKEN>",
  "user": {
    "id": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
    "email": "john@example.com",
    "full_name": "John Doe",
    "phone_number": "01700000000",
    "account_status": "active",
    "is_active": true,
    "created_at": "2026-05-03T16:00:00.000Z",
    "updated_at": "2026-05-03T16:00:00.000Z"
  }
}
```

#### Example Error (401)

```json
{
  "error": {
    "code": "INVALID_REFRESH_TOKEN",
    "message": "Invalid or expired refresh token"
  }
}
```

---

## 5) Get Current User

### GET `/users/me`

Returns the authenticated user profile (same `user` shape as auth endpoints).

#### Headers

```http
Content-Type: application/json
Authorization: Bearer <JWT_ACCESS_TOKEN>
```

#### Body

No request body.

#### Success Response (200)

```json
{
  "user": {
    "id": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
    "email": "john@example.com",
    "full_name": "John Doe",
    "phone_number": "01700000000",
    "account_status": "active",
    "is_active": true,
    "created_at": "2026-05-03T16:00:00.000Z",
    "updated_at": "2026-05-03T16:00:00.000Z"
  }
}
```

#### Example Error (401)

```json
{
  "error": {
    "code": "AUTH_HEADER_INVALID",
    "message": "Missing or invalid Authorization header"
  }
}
```

---

## 6) Assign Role to User (Admin Permission Required)

### POST `/users/:userId/roles`

Assigns a role to another user by user public UUID.

Required permission: `auth.manage_roles`

#### Headers

```http
Content-Type: application/json
Authorization: Bearer <JWT_ACCESS_TOKEN_WITH_AUTH_MANAGE_ROLES>
```

#### Path Params

- `userId` (UUID): target user public UUID

#### Body

```json
{
  "roleCode": "dispatcher"
}
```

#### Success Response (200)

```json
{
  "message": "Role assigned successfully",
  "userId": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
  "roleCode": "dispatcher"
}
```

#### Example Error (403)

```json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "Missing required permission"
  }
}
```

#### Example Error (404)

```json
{
  "error": {
    "code": "ROLE_NOT_FOUND",
    "message": "Role not found"
  }
}
```

---

## Dev RBAC Bootstrap Notes

On server start, backend seeds minimal RBAC data and tries to bootstrap a development admin user.

Required env vars:

- `SYSTEM_ADMIN__EMAIL`
- `SYSTEM_ADMIN_PASSWORD`
- `SYSTEM_ADMIN_NAME`
- `SYSTEM_ADMIN_PHONE` (must be exactly 11 digits)

If no current `system_admin` assignment exists and these env vars are set, the app will create/find the user and assign `system_admin`.

---

## 7) Create Intake Report

### POST `/intake/reports`

Creates an `intake_reports` row for the authenticated user (reporter). Requires a valid JWT (any authenticated account). New reports start with `intake_status` **`received`**. Implementation: `backend/src/repositories/intakeRepo.js` (see **INTAKE-001** in `docs/tickets-intake-gateway-fe-db.md`).

#### Headers

```http
Content-Type: application/json
Authorization: Bearer <ACCESS_TOKEN>
```

#### Body

Option A (recommended for now): send a typed address string.

```json
{
  "channelCode": "web_portal",
  "categoryCode": "medical",
  "summary": "Road blocked by fallen tree",
  "description": "Optional longer text",
  "urgencyType": "non_emergency",
  "reportedAt": "2026-05-04T12:00:00.000Z",
  "location": "House 12, Road 3, Dhanmondi, Dhaka"
}
```

Option B: send the structured location object (existing format).

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
    "address_text": "Dhaka",
    "place_name": "Optional label",
    "admin_area_id": 1,
    "source": "user_shared"
  }
}
```

- `urgencyType`: `non_emergency` | `emergency` | `unknown` (optional; default `unknown`). **Portal / citizen callers must not send `emergency`:** only users with permission `incident.classify` (e.g. **dispatcher**, **system_admin** per bootstrap) may set that value. Everyone else should use `unknown` or `non_emergency`; an operator promotes the report to the emergency path using `POST /intake/reports/:reportPublicUuid/classify/emergency` when appropriate.
- `reportedAt`: optional ISO datetime.
- `location`: optional on create, accepts either:
  - a non-empty string (typed by citizen/dispatcher), or
  - an object with `latitude`, `longitude`, `address_text`, optional `place_name`, optional `admin_area_id`, optional `source`.
- If `location` is provided as a string, backend currently stores it as `locations.address_text` and uses temporary `0/0` coordinates until map integration is added.
- `location` should be provided if the report may later take the emergency classification path (`current_location_id` on `emergency_incidents` is NOT NULL).

#### Success Response (201)

`intake` is the inserted row from `intake_reports` (MySQL column names, e.g. `public_uuid`, `report_code`, `intake_status`, `urgency_type`, `reported_at`, plus internal ids such as `channel_id` / `category_id`).

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

#### Example Error (422 — invalid channel or category)

`REPORT_CHANNEL_NOT_FOUND` or `REPORT_CATEGORY_NOT_FOUND` when `channelCode` / `categoryCode` is missing from seed data or inactive.

#### Example Error (422)

Validation failures use `VALIDATION_ERROR` with `details` (standard shape).

#### Example Error (403 — emergency urgency not allowed for portal user)

```json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "Missing required permission"
  }
}
```

Sent when `urgencyType` is `emergency` but the token does not include `incident.classify`.

---

## 8) Get My Intake Reports

### GET `/intake/reports/my`

Returns all intake reports created by the authenticated user (newest first).

#### Headers

```http
Content-Type: application/json
Authorization: Bearer <ACCESS_TOKEN>
```

#### Body

No request body.

#### Success Response (200)

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
      "location_text": "House 12, Road 3, Dhanmondi, Dhaka"
    }
  ]
}
```

---

## 9) Get My Intake Report Stats

### GET `/intake/reports/my/stats`

Returns dashboard counters for the authenticated user.

#### Headers

```http
Content-Type: application/json
Authorization: Bearer <ACCESS_TOKEN>
```

#### Body

No request body.

#### Success Response (200)

```json
{
  "stats": {
    "totalReports": 5,
    "pendingReports": 3,
    "resolvedReports": 2
  }
}
```

---

## 10) Classify Intake → Service Case (Non-Emergency)

### POST `/intake/reports/:reportPublicUuid/classify/service-case`

Branches an existing intake into a **service case**. **Required role:** `dispatcher` or `system_admin` (citizens cannot call this endpoint).

SQL / flow: **INTAKE-002** in `docs/tickets-intake-gateway-fe-db.md` (`createServiceCaseFromIntake` in `backend/src/repositories/intakeGatewayRepo.js`).

#### Headers

```http
Content-Type: application/json
Authorization: Bearer <ACCESS_TOKEN>
```

#### Path Params

- `reportPublicUuid` — intake `public_uuid` (UUID).

#### Body

```json
{
  "title": "Optional override title",
  "description": "Optional",
  "priorityLevel": "medium"
}
```

If `title` is omitted, the service uses the intake `summary`.

#### Success Response (201)

```json
{
  "message": "Intake classified as service case",
  "service_case": {},
  "intake": {}
}
```

`service_case` and `intake` are full rows from `service_cases` and `intake_reports` respectively (column names match the database).

#### Example Error (409)

```json
{
  "error": {
    "code": "INTAKE_NOT_CLASSIFIABLE",
    "message": "Intake report cannot be classified in its current status"
  }
}
```

#### Example Error (422)

`SERVICE_CASE_REQUIRES_REPORTER_USER` if the intake has no `reporter_user_id` (schema requires it on `service_cases`).

#### Example Error (403)

```json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "Missing required role"
  }
}
```

Returned when the authenticated user is neither `dispatcher` nor `system_admin`.

---

## 11) Classify Intake → Emergency Path (999)

### POST `/intake/reports/:reportPublicUuid/classify/emergency`

Branches an intake into the **999 / emergency** path: creates `emergency_calls`, `emergency_incidents`, and `incident_report_links`, and moves intake to `linked_to_incident`. **Required role:** `dispatcher` or `system_admin` only (not merely `incident.create`; citizens and other roles cannot call this even if they somehow hold other permissions). Same roles apply when escalating an intake already `linked_to_case` to the emergency path.

SQL / flow: **INTAKE-003** in `docs/tickets-intake-gateway-fe-db.md` (`createEmergency999PathFromIntake` in `backend/src/repositories/intakeGatewayRepo.js`).

#### Headers

```http
Content-Type: application/json
Authorization: Bearer <ACCESS_TOKEN>
```

#### Path Params

- `reportPublicUuid` — intake `public_uuid` (UUID).

#### Body

```json
{
  "severityCode": "high",
  "incidentTitle": "Optional override",
  "incidentDescription": "Optional",
  "callerPhoneNumber": "01700000000",
  "callStartedAt": "2026-05-04T12:05:00.000Z"
}
```

- `severityCode`: `low` | `medium` | `high` | `critical` (matches `incident_severity_levels.severity_code` seeds).

#### Success Response (201)

```json
{
  "message": "Intake classified on emergency (999) path",
  "emergency_call": {},
  "emergency_incident": {},
  "incident_report_link": {},
  "intake": {}
}
```

Each object is a row from the corresponding table (`emergency_calls`, `emergency_incidents`, `incident_report_links`, `intake_reports`).

#### Example Error (422)

`EMERGENCY_INCIDENT_REQUIRES_LOCATION` when the intake has no `reported_location_id`.

#### Example Error (403)

```json
{
  "error": {
    "code": "FORBIDDEN",
    "message": "Missing required role"
  }
}
```

Returned when the authenticated user is neither `dispatcher` nor `system_admin`.

---

## 12) Dispatcher Overview (operations dashboard)

### GET `/operations/dispatcher/overview`

Read-only rollup for dispatcher UIs: summary **counts** and a **recent** timeline merged from intake reports pending classification, non-terminal emergency incidents, and open service cases. **Required permission:** `incident.classify` (dispatcher and system administrator roles receive this permission in seeded RBAC).

#### Headers

```http
Content-Type: application/json
Authorization: Bearer <ACCESS_TOKEN>
```

#### Count semantics (`counts`)

| Field | Predicate |
| --- | --- |
| `intake_reports_pending_classification` | `intake_reports.intake_status` is `received` **or** `under_review`. |
| `incidents_active` | Current `incident_statuses.is_terminal` is `FALSE`. |
| `service_cases_open` | Current `case_statuses.is_terminal` is `FALSE` (aligned with queue logic used by `vw_admin_case_queue`). |

#### Recent timeline (`recent`)

Each source loads up to **10** newest rows (`reported_at` for intakes/incidents; `created_at` for service cases). The backend merges rows by **`occurred_at`** descending (ISO 8601) and returns at most **15** items.

Every element:

| Field | Notes |
| --- | --- |
| `kind` | `intake_report` \| `incident` \| `service_case`. |
| `public_uuid` | Public identifier for correlation with other `/operations/*` payloads. |
| `summary` | Intake summary, incident title, or service-case title (empty string allowed). |
| `status` | Intake uses `intake_status`; incidents use incident `status_code`; service cases use case `status_code`. |
| `category` | `report_categories.category_code` for each entity. |
| `occurred_at` | Canonical sort key normalized to UTC ISO timestamps. |
| `age_minutes` | Whole minutes elapsed between `TIMESTAMPDIFF` anchors used in repositories (reported versus created timestamps per kind). |

#### Success Response (200)

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

---

## 13) List Intake Reports (Operations Queue)

### GET `/operations/intake-reports`

Paginated dispatcher / operations queue of all intake reports. **Required permission:** `incident.classify`.

#### Headers

```http
Content-Type: application/json
Authorization: Bearer <ACCESS_TOKEN>
```

#### Query params (optional)

| Param | Notes |
| --- | --- |
| `intake_status` | Filter by intake status string |
| `urgency_type` | `non_emergency` \| `emergency` \| `unknown` |
| `categoryCode` | Matches seeded `report_categories.category_code` |
| `limit` | 1–100 (default 50) |
| `offset` | Non-negative integer |
| `sort` | `reported_at_desc` (default) \| `reported_at_asc` |

#### Success Response (200)

```json
{
  "intake_reports": [
    {
      "public_uuid": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
      "report_code": "IR-MA4SJP2K-9C2E2EAA",
      "reporter_user_id": "1",
      "urgency_type": "non_emergency",
      "summary": "Road blocked",
      "description": null,
      "intake_status": "received",
      "final_disposition": null,
      "channel_code": "web_portal",
      "category_code": "medical",
      "has_service_case": false,
      "has_incident": false,
      "reported_at": "2026-05-04T12:00:00.000Z",
      "created_at": "2026-05-04T12:00:00.000Z",
      "updated_at": "2026-05-04T12:00:00.000Z"
    }
  ],
  "pagination": { "limit": 50, "offset": 0, "total": 1 }
}
```

#### Example Error (403)

Missing `incident.classify`: `FORBIDDEN` / `Missing required permission`.

---

## 14) Get Intake Report (Operations)

### GET `/operations/intake-reports/:reportPublicUuid`

Single intake row in the same shape as list items. **Required permission:** `incident.classify`.

#### Path params

- `reportPublicUuid` — UUID

#### Success Response (200)

```json
{
  "intake_report": {
    "public_uuid": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
    "report_code": "IR-MA4SJP2K-9C2E2EAA",
    "reporter_user_id": "1",
    "urgency_type": "non_emergency",
    "summary": "Road blocked",
    "description": null,
    "intake_status": "received",
    "final_disposition": null,
    "channel_code": "web_portal",
    "category_code": "medical",
    "has_service_case": false,
    "has_incident": false,
    "reported_at": "2026-05-04T12:00:00.000Z",
    "created_at": "2026-05-04T12:00:00.000Z",
    "updated_at": "2026-05-04T12:00:00.000Z"
  }
}
```

#### Example Error (404)

`INTAKE_REPORT_NOT_FOUND`

---

## 15) Promote Intake to Emergency (Operations)

### POST `/operations/intake-reports/:reportPublicUuid/promote/emergency`

Creates an `emergency_incidents` row from an existing intake **without** an `emergency_calls` row (note is stored on the incident link — “Promoted on emergency path (no call record)”). Intake must be in `received`, `under_review`, or `linked_to_case`, must already have `reported_location_id`, and must not already be linked to an incident.

**Required permissions:** both `incident.create` **and** `incident.classify`.

#### Headers

```http
Content-Type: application/json
Authorization: Bearer <ACCESS_TOKEN>
```

#### Path params

- `reportPublicUuid` — intake `public_uuid` (UUID)

#### Body

```json
{
  "severityCode": "high",
  "incidentTitle": "Unconscious patient near gate 2",
  "incidentDescription": "Security team found a person unresponsive and requested ambulance support.",
  "callerPhoneNumber": "+8801700000000",
  "callStartedAt": "2026-05-04T12:03:00.000Z",
  "reportedAt": "2026-05-04T12:05:00.000Z"
}
```

#### Success Response (201)

Returns the created incident snapshot (`mapIncidentDetail` shape):

```json
{
  "message": "Intake promoted to emergency incident",
  "incident": {
    "public_uuid": "…",
    "incident_code": "EMI-…",
    "title": "…",
    "description": null,
    "origin_type": "admin_created",
    "status_code": "reported",
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

#### Example Error (422)

`EMERGENCY_INCIDENT_REQUIRES_LOCATION` if the intake has no location.

#### Example Error (409)

`INTAKE_NOT_PROMOTABLE` (wrong intake status), or `INTAKE_ALREADY_LINKED`.

---

## 16) Create Emergency Incident (Operations)

### POST `/operations/incidents`

Creates a standalone **or** intake-linked emergency incident. **Required permission:** `incident.create`.

#### Body (choose one mode)

**A — Link an existing intake** (uses intake category + location; intake must be promotable and not already linked):

```json
{
  "severityCode": "high",
  "intakeReportPublicUuid": "0d5fd834-a3fc-4180-b8ec-a6e664d130d0",
  "title": "Optional; defaults to intake summary",
  "description": "Optional",
  "reportedAt": "2026-05-04T12:00:00.000Z"
}
```

**B — Standalone incident** (no intake):

```json
{
  "categoryCode": "medical",
  "severityCode": "high",
  "title": "Worker collapsed near loading dock",
  "description": "On-site medic requested immediate ambulance dispatch.",
  "reportedAt": "2026-05-04T12:00:00.000Z",
  "location": "House 12, Road 3, Dhanmondi, Dhaka"
}
```

Location object matches intake create: `latitude`, `longitude`, `address_text`, optional `place_name`, `admin_area_id`, optional `source` (`user_shared` \| `dispatcher_selected` \| `api_geocoded` \| `manual_entry`).

#### Success Response (201)

```json
{
  "message": "Incident created",
  "incident": {}
}
```

`incident` matches the detail object returned by promote/create (see §17 `incident`).

#### Example Error (422)

`REPORT_CATEGORY_NOT_FOUND`, `LOCATION_REQUIRED`, `INCIDENT_TITLE_REQUIRED`, `EMERGENCY_INCIDENT_REQUIRES_LOCATION`, etc., depending on mode and payload.

---

## 17) List Emergency Incidents (Operations)

### GET `/operations/incidents`

**Required permission:** `incident.create` **or** `incident.update_status` (either is sufficient).

#### Query params (optional)

| Param | Notes |
| --- | --- |
| `status_code` | Current incident status code |
| `reported_after` | ISO datetime with offset |
| `reported_before` | ISO datetime with offset |
| `limit` | 1–100 (default 50) |
| `offset` | Non-negative integer |

Results are ordered by `reported_at` descending.

#### Success Response (200)

```json
{
  "incidents": [
    {
      "public_uuid": "…",
      "incident_code": "EMI-…",
      "title": "…",
      "description": null,
      "origin_type": "admin_created",
      "status_code": "reported",
      "category_code": "medical",
      "severity_code": "high",
      "reported_at": "2026-05-04T12:00:00.000Z",
      "resolved_at": null,
      "closed_at": null,
      "created_at": "2026-05-04T12:00:01.000Z",
      "updated_at": "2026-05-04T12:00:01.000Z"
    }
  ],
  "pagination": { "limit": 50, "offset": 0, "total": 1 }
}
```

---

## 18) Get Emergency Incident (Operations)

### GET `/operations/incidents/:incidentPublicUuid`

**Required permission:** `incident.create` **or** `incident.update_status`.

#### Success Response (200)

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

`incident` is the full detail object; timeline is capped (last 50 events by `event_time`).

#### Example Error (404)

`INCIDENT_NOT_FOUND`

---

## 19) Patch Emergency Incident Status (Operations)

### PATCH `/operations/incidents/:incidentPublicUuid/status`

Updates current status with server-side transition rules. **Required permission:** `incident.update_status`.

#### Body

```json
{
  "statusCode": "in_progress",
  "note": "Optional note stored in status history",
  "outcomeCode": "resolved"
}
```

- `outcomeCode` is only accepted when moving to **`resolved`**, **`closed`**, or **`cancelled`**. Allowed values: `resolved`, `false_alarm`, `duplicate_incident`, `cancelled`, `transferred`, `unresolved`.
- Allowed transitions (from → to):
  - `reported` → `classified`, `cancelled`
  - `classified` → `in_progress`, `resolved`, `closed`, `cancelled`
  - `in_progress` → `resolved`, `closed`, `cancelled`
- Terminal statuses (`resolved`, `closed`, `cancelled`) cannot be changed further.

#### Success Response (200)

```json
{
  "message": "Incident status updated",
  "incident": {}
}
```

#### Example Error (409)

`INVALID_STATUS_TRANSITION` (illegal transition, terminal incident, or same status as current).

---

## 20) Add Operator Note to Incident (Operations)

### POST `/operations/incidents/:incidentPublicUuid/notes`

Appends an `operator_note` row to `incident_timeline_events`. **Required permission:** `incident.update_status`.

#### Body

```json
{
  "title": "Radio check",
  "description": "Optional body",
  "eventTime": "2026-05-04T14:00:00.000Z"
}
```

`title` is required (max 255 chars). `eventTime` is optional ISO datetime; defaults to “now” if omitted.

#### Success Response (201)

```json
{
  "message": "Operator note added",
  "note": {
    "id": "42",
    "event_type": "operator_note",
    "event_title": "Radio check",
    "event_description": null
  }
}
```

#### Example Error (404)

`INCIDENT_NOT_FOUND`