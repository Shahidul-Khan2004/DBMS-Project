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

Creates a new user and returns JWT tokens + authorization context.

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
    "is_active": true,
    "created_at": "2026-05-03T16:00:00.000Z",
    "updated_at": "2026-05-03T16:00:00.000Z"
  },
  "authz": {
    "roleCodes": ["citizen"],
    "permissions": []
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

Authenticates user credentials and returns JWT tokens + authorization context.

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
    "is_active": true,
    "created_at": "2026-05-03T16:00:00.000Z",
    "updated_at": "2026-05-03T16:00:00.000Z"
  },
  "authz": {
    "roleCodes": ["citizen"],
    "permissions": []
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
    "is_active": true,
    "created_at": "2026-05-03T16:00:00.000Z",
    "updated_at": "2026-05-03T16:00:00.000Z"
  },
  "authz": {
    "roleCodes": ["citizen"],
    "permissions": []
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

Returns profile + RBAC context of the authenticated user.

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
    "is_active": true,
    "created_at": "2026-05-03T16:00:00.000Z",
    "updated_at": "2026-05-03T16:00:00.000Z"
  },
  "authz": {
    "roleCodes": ["dispatcher"],
    "permissions": [
      "incident.create",
      "incident.classify",
      "incident.assign_agency",
      "incident.update_status",
      "dispatch.create",
      "dispatch.update_status"
    ]
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

If no current `system_admin` assignment exists and these env vars are set, the app will create/find the user and assign `system_admin`.

