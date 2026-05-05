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

Creates an `intake_reports` row for the authenticated user (reporter). Intended permissions when RBAC is enforced: authenticated **citizen** (or any role allowed to submit portal reports).

Repository SQL is tracked in **INTAKE-001** (`docs/tickets-intake-gateway-fe-db.md`). Until implemented, the handler responds with **501** and `INTAKE_REPOSITORY_PENDING`.

#### Headers

```http
Content-Type: application/json
Authorization: Bearer <ACCESS_TOKEN>
```

#### Body

```json
{
  "channelCode": "web_portal",
  "categoryCode": "relief_request",
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
- `location`: optional on create, but **required** if the same report will later take the emergency classification path (`current_location_id` on `emergency_incidents` is NOT NULL).

#### Success Response (201)

Shape depends on repository return value; minimally:

```json
{
  "message": "Intake report created",
  "intake": {
    "public_uuid": "…",
    "report_code": "IR-…",
    "intake_status": "received",
    "urgency_type": "non_emergency",
    "reported_at": "2026-05-04T12:00:00.000Z"
  }
}
```

#### Example Error (501 — repository not wired)

```json
{
  "error": {
    "code": "INTAKE_REPOSITORY_PENDING",
    "message": "createIntakeReport is not implemented; complete INTAKE-001 in docs/tickets-intake-gateway-fe-db.md"
  }
}
```

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

## 8) Classify Intake → Service Case (Non-Emergency)

### POST `/intake/reports/:reportPublicUuid/classify/service-case`

Branches an existing intake into a **service case**. Intended permission when RBAC is enforced: `case.create`.

SQL: **INTAKE-002** in `docs/tickets-intake-gateway-fe-db.md`. Until implemented: **501** `INTAKE_GATEWAY_REPOSITORY_PENDING`.

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

(Exact fields follow repository implementation.)

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

---

## 9) Classify Intake → Emergency Path (999)

### POST `/intake/reports/:reportPublicUuid/classify/emergency`

Branches an intake into the **999 / emergency** path: creates `emergency_calls`, `emergency_incidents`, and `incident_report_links`, and moves intake to `linked_to_incident`. **Required permission:** `incident.create`. This is **not** available to default **citizen** accounts; use a **dispatcher** or **system_admin** token (see bootstrap role grants). Web-portal citizens cannot open the emergency incident path themselves.

SQL: **INTAKE-003** in `docs/tickets-intake-gateway-fe-db.md`. Until implemented: **501** `INTAKE_GATEWAY_REPOSITORY_PENDING`.

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

#### Example Error (422)

`EMERGENCY_INCIDENT_REQUIRES_LOCATION` when the intake has no `reported_location_id`.

#### Example Error (403)

`FORBIDDEN` / `Missing required permission` when the token lacks `incident.create`.

