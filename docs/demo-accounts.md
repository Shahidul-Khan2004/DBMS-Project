# Demo and bootstrap accounts

Development accounts are **not** stored in SQL seed files. They are created on **backend startup** when the matching environment variables are set in [`backend/.env`](../backend/.env).

Copy [`backend/.env.example`](../backend/.env.example) as a starting point. Passwords below are the **example values** from that file; your local `.env` may differ.

## Quick reference

| Email | Role | Password env var | Example password |
|-------|------|------------------|------------------|
| Value of `SYSTEM_ADMIN__EMAIL` (default `admin@example.com`) | `system_admin` | `SYSTEM_ADMIN_PASSWORD` | `ChangeMeAdmin123` |
| `dispatcher@niers.test` | `dispatcher` | `DEMO_DISPATCHER_PASSWORD` | `ChangeMeDispatcher123` |
| `fire.rep@niers.test` | `agency_representative` | `DEMO_REP_PASSWORD` | `ChangeMeDemoRep123` |
| `police.rep@niers.test` | `agency_representative` | `DEMO_REP_PASSWORD` | `ChangeMeDemoRep123` |
| `medical.rep@niers.test` | `agency_representative` | `DEMO_REP_PASSWORD` | `ChangeMeDemoRep123` |
| `relief.rep@niers.test` | `agency_representative` | `DEMO_REP_PASSWORD` | `ChangeMeDemoRep123` |
| `shelter.rep@niers.test` | `agency_representative` | `DEMO_REP_PASSWORD` | `ChangeMeDemoRep123` |

All demo passwords (`DEMO_*`) must be **at least 8 characters** or bootstrap is skipped.

---

## System administrator

Created only when **no** active `system_admin` user exists yet.

| Field | Source |
|-------|--------|
| Email | `SYSTEM_ADMIN__EMAIL` |
| Password | `SYSTEM_ADMIN_PASSWORD` |
| Display name | `SYSTEM_ADMIN_NAME` |
| Phone | `SYSTEM_ADMIN_PHONE` (exactly 11 digits) |

**Bootstrap:** [`backend/src/services/bootstrapService.js`](../backend/src/services/bootstrapService.js)

**Example login** (from `.env.example`):

- Email: `admin@example.com`
- Password: `ChangeMeAdmin123`