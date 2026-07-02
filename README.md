# NIERS

**National Integrated Emergency Response System**

A full-stack platform for centralized citizen reporting, 999 call intake, and coordinated emergency and disaster response — built as a DBMS course project with production-oriented patterns.

**[Watch the demo on YouTube](https://youtu.be/jeReSWqZ61Y?si=yUixp27D8HSAoPUM)**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Overview

NIERS connects citizens, dispatchers, response agencies, and system administrators on a shared workflow: report → classify → dispatch → resolve. The system supports routine service cases, active emergency incidents, national disaster declarations, GPS-based location resolution for Bangladesh, and role-based access control across every dashboard.

| Role | Portal |
|------|--------|
| **Citizen** | Submit reports, track incidents and service cases, manage saved locations |
| **Dispatcher** | 999 gateway, intake classification, incident and service-case operations, disaster linking |
| **Agency representative** | Dispatches, field updates, response logs, national-disaster coordination |
| **System admin** | Agency onboarding, facilities, reporter-risk oversight, role assignment, disaster administration |

---

## Features

- **Citizen intake** — structured reports with optional GPS; automatic administrative-area resolution
- **999 gateway** — dispatcher workflow for emergency call intake
- **Dual-track operations** — emergency incidents and non-emergency service cases with escalation paths
- **National disaster mode** — declare disasters, link reports, coordinate multi-agency response and facilities
- **RBAC** — JWT auth with refresh tokens, permissions, and agency-scoped context
- **Notifications & email queue** — BullMQ worker backed by Redis for async mail delivery
- **Bangladesh geography** — full admin hierarchy (division → union) seeded from open data
- **Demo & showcase seeds** — bootstrap accounts and operational demo data for presentations

---

## Tech stack

| Layer | Technologies |
|-------|--------------|
| **Frontend** | [Next.js 16](https://nextjs.org/), React 19, TypeScript, Tailwind CSS 4, Leaflet |
| **Backend** | [Node.js](https://nodejs.org/) (ES modules), [Express 5](https://expressjs.com/), Zod validation |
| **Database** | MySQL 8 (local Docker), PostgreSQL/Supabase (deploy); ordered SQL init fragments |
| **Queue / cache** | Redis 7, BullMQ |
| **Auth** | JWT (access + refresh), bcrypt |
| **Integrations** | Barikoi reverse geocoding (optional), Nodemailer (SMTP) |

---

## Architecture

The backend follows a layered Express architecture: routes → middleware (auth, RBAC, validation) → controllers → services → repositories → MySQL. Business rules and orchestration live in services; SQL stays in repositories.

```
Client (Next.js :3000)
        │
        ▼
   Express API (:8080)
        │
   ┌────┴────┬──────────┐
   ▼         ▼          ▼
 MySQL     Redis    Barikoi / SMTP
```

Frontend pages live under `frontend/app/` with role-specific dashboards. The API base URL defaults to `http://localhost:8080` (`NEXT_PUBLIC_API_BASE_URL`).

---

## Project structure

```
.
├── backend/
│   ├── docker-compose.yml      # MySQL + Redis
│   ├── src/
│   │   ├── api/                # routes, controllers, middlewares, validators
│   │   ├── services/           # business logic
│   │   ├── repositories/       # parameterized SQL
│   │   ├── schemas/docker-init/  # ordered MySQL init & seeds
│   │   ├── integrations/       # Barikoi, mail
│   │   └── workers/            # email queue consumer
│   └── test/                   # unit + integration tests
├── frontend/
│   ├── app/                    # Next.js App Router pages
│   ├── components/             # UI by role (citizen, dispatcher, agency, admin)
│   └── lib/                    # API client, hooks, utilities
├── docs/                       # API reference, demo accounts, dependencies
├── supabase-postgres-migration/  # PostgreSQL SQL for Supabase/Render deploy
└── package.json                # root scripts & shared dependencies
```

---

## Getting started

### Prerequisites

- **Node.js** 20+ (recommended)
- **Docker** and Docker Compose (for MySQL and Redis)
- **npm**

### Quick start (local showcase)

Copy-paste from a fresh clone — no manual env editing required:

```bash
git clone https://github.com/Shahidul-Khan2004/DBMS-Project.git
cd DBMS-Project
npm install
cp backend/.env.example backend/.env
cd backend && docker compose up -d && cd ..
npm run dev:backend   # terminal 1 — http://localhost:8080
npm run dev:frontend  # terminal 2 — http://localhost:3000
```

First Docker start may take a few minutes while MySQL loads schema and Bangladesh admin-area seeds (~5k rows). Demo accounts and showcase data are created automatically on backend startup.

### Step-by-step

**1. Clone and install**

```bash
git clone https://github.com/Shahidul-Khan2004/DBMS-Project.git
cd DBMS-Project
npm install
```

**2. Configure environment** (before Docker)

```bash
cp backend/.env.example backend/.env
```

[`backend/.env.example`](backend/.env.example) ships with working local defaults (`MYSQL_*`, JWT secrets, demo passwords). You only need to edit it for production deploy, custom credentials, Barikoi GPS, or SMTP.

**3. Start database services**

```bash
cd backend
docker compose up -d
```

Compose reads `MYSQL_ROOT_PASSWORD`, `MYSQL_USER`, `MYSQL_PASSWORD`, and `MYSQL_DATABASE` from `backend/.env`.

On first start with an empty volume, MySQL runs every `*.sql` file in `backend/src/schemas/docker-init/` in lexical order. See [backend/src/schemas/README.md](backend/src/schemas/README.md) for the seed layout.

To reset the database after schema changes:

```bash
docker compose down -v
docker compose up -d
```

**4. Run the application**

From the repository root, in separate terminals:

```bash
# API server (http://localhost:8080)
npm run dev:backend

# Web app (http://localhost:3000)
npm run dev:frontend
```

On backend startup, RBAC seeds and demo accounts are bootstrapped when the corresponding env vars are set.

### Showcase login credentials

Use these with a default [`backend/.env.example`](backend/.env.example) copy. Full role list: [docs/demo-accounts.md](docs/demo-accounts.md).

| Email | Role | Password |
|-------|------|----------|
| `admin@example.com` | System admin | `ChangeMeAdmin123` |
| `dispatcher@niers.test` | Dispatcher | `ChangeMeDispatcher123` |
| `citizen.rahima@niers.test` | Citizen | `ChangeMeCitizen123` |
| `fire.rep@niers.test` | Agency rep | `ChangeMeDemoRep123` |

**What works without extra setup:** all dashboards, seeded incidents and service cases, disaster admin flows, Bangladesh geography, and reporter-risk demo data.

**Optional (not required for showcase):** `BARIKOI_API_KEY` for live GPS → admin-area resolution; SMTP + `EMAIL_QUEUE_ENABLED=true` for outbound email.

### Deployed demo (Supabase / Render)

Local development uses **MySQL in Docker**. For a hosted demo, apply PostgreSQL SQL from [`supabase-postgres-migration/`](supabase-postgres-migration/) to Supabase and set `DB_DIALECT=postgres` plus `DATABASE_URL` on the backend. See that folder’s README for apply order and env vars.

---

## Testing

From the repository root:

```bash
# Fast contract & unit tests (no MySQL required)
npm test

# HTTP smoke tests against Docker MySQL + backend/.env
npm run test:integration

# Optional: verify Barikoi API key (requires network)
npm run test:barikoi-live
```

Integration tests require MySQL running, a configured `backend/.env`, and demo password env vars. Details: [backend/README.md](backend/README.md#testing).

---

## Documentation

| Document | Description |
|----------|-------------|
| [docs/README.md](docs/README.md) | Documentation index |
| [docs/backend-api.md](docs/backend-api.md) | HTTP API reference |
| [docs/demo-accounts.md](docs/demo-accounts.md) | Bootstrap demo accounts & showcase seed |
| [docs/backend-external-dependencies.md](docs/backend-external-dependencies.md) | Barikoi, geocode data, SMTP |
| [backend/README.md](backend/README.md) | Database Docker setup, admin-area regeneration |
| [supabase-postgres-migration/README.md](supabase-postgres-migration/README.md) | PostgreSQL deploy to Supabase/Render |

---

## Maintainer scripts

```bash
# Regenerate Bangladesh administrative_areas seed from upstream JSON (network required)
npm run generate:admin-areas

# Production frontend build
npm run build:frontend
npm run start:frontend
```

---

## Third-party data

Bangladesh administrative hierarchy data is derived from [nuhil/bangladesh-geocode](https://github.com/nuhil/bangladesh-geocode) (MIT). See [backend/third_party/bangladesh-geocode/README.md](backend/third_party/bangladesh-geocode/README.md).

---

## Contributing

Contributions are welcome. For substantial changes:

1. Fork the repository and create a feature branch.
2. Keep changes focused; match existing naming and layer boundaries in the backend.
3. Run `npm test` before opening a pull request; add or update integration tests when behavior changes.
4. Update [docs/backend-api.md](docs/backend-api.md) when HTTP contracts change.

Please do not commit secrets (`.env`, API keys, or credentials).

---

## License

This project is licensed under the [MIT License](LICENSE).

Copyright (c) 2026 Shahidul Islam Khan
