# Demo and bootstrap accounts

Development accounts are **not** stored in SQL seed files. They are created on **backend startup** when the matching environment variables are set in [`backend/.env`](../backend/.env).

Copy [`backend/.env.example`](../backend/.env.example) as a starting point. Passwords below are the **example values** from that file; your local `.env` may differ.

## Quick reference

| Email | Role | Password env var | Example password |
|-------|------|------------------|------------------|
| Value of `SYSTEM_ADMIN__EMAIL` (default `admin@example.com`) | `system_admin` | `SYSTEM_ADMIN_PASSWORD` | `ChangeMeAdmin123` |
| `dispatcher@niers.test` | `dispatcher` | `DEMO_DISPATCHER_PASSWORD` | `ChangeMeDispatcher123` |
| `citizen.rahima@niers.test` | `citizen` | `DEMO_CITIZEN_PASSWORD` | `ChangeMeCitizen123` |
| `citizen.karim@niers.test` | `citizen` | `DEMO_CITIZEN_PASSWORD` | `ChangeMeCitizen123` |
| `citizen.farhana@niers.test` | `citizen` | `DEMO_CITIZEN_PASSWORD` | `ChangeMeCitizen123` |
| `citizen.rubel@niers.test` | `citizen` | `DEMO_CITIZEN_PASSWORD` | `ChangeMeCitizen123` |
| `citizen.shamim@niers.test` | `citizen` | `DEMO_CITIZEN_PASSWORD` | `ChangeMeCitizen123` |
| `fire.rep@niers.test` | `agency_representative` | `DEMO_REP_PASSWORD` | `ChangeMeDemoRep123` |
| `police.rep@niers.test` | `agency_representative` | `DEMO_REP_PASSWORD` | `ChangeMeDemoRep123` |
| `medical.rep@niers.test` | `agency_representative` | `DEMO_REP_PASSWORD` | `ChangeMeDemoRep123` |
| `relief.rep@niers.test` | `agency_representative` | `DEMO_REP_PASSWORD` | `ChangeMeDemoRep123` |
| `shelter.rep@niers.test` | `agency_representative` | `DEMO_REP_PASSWORD` | `ChangeMeDemoRep123` |

All demo passwords (`DEMO_*`) must be **at least 8 characters** or bootstrap is skipped.

---

## Showcase seed (day-to-day operations)

When `DEMO_CITIZEN_PASSWORD` is set, the backend also applies operational demo SQL (`29`–`32` in [`docker-init/`](../backend/src/schemas/docker-init/)) after creating demo citizens.

**What is pre-seeded**

- Routine intakes (medical, fire, road safety, relief follow-up)
- One open service case (`SC-KUR-SHOW-001`) with citizen messages
- Three active Kurigram incidents (`EMI-KUR-PRE-001` … `003`) with dispatches and response logs
- Kurigram agencies, units, and facilities from seed `28` (master data only)

**What is not pre-seeded**

- No `disaster_events` rows — `GET /public/disasters` returns an empty list until a disaster is **declared live**
- No `natural_disaster` category on showcase intakes/incidents (reserved for live disaster demo)
- No flood/mass-evacuation narratives — presenter creates and declares the disaster during the showcase

**Pending dispatcher work:** intakes `IR-KUR-SHOW-003` (potholes) and `IR-KUR-SHOW-005` (child fever).

---

## Demo citizens

| Email | Name | Phone |
|-------|------|-------|
| `citizen.rahima@niers.test` | Rahima Begum | `01710000001` |
| `citizen.karim@niers.test` | Abdul Karim | `01710000002` |
| `citizen.farhana@niers.test` | Farhana Akter | `01710000003` |
| `citizen.rubel@niers.test` | Rubel Hossain | `01710000004` |
| `citizen.shamim@niers.test` | Shamim Ahmed | `01710000005` |

**Reporter risk demo personas** (seed `32`, after bootstrap):

| Citizen | Risk profile |
|---------|----------------|
| Rahima Begum | Genuine reports, low risk |
| Abdul Karim | Duplicate reports |
| Farhana Akter | False alarms, medium risk (warning recorded) |
| Rubel Hossain | Repeated false alarms |
| Shamim Ahmed | Malicious spam, high risk, 30-day timed suspension |

**Bootstrap:** [`demoCitizenBootstrapService.js`](../backend/src/services/demoCitizenBootstrapService.js)

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
