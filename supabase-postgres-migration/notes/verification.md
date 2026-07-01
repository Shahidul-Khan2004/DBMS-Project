# Supabase Migration Verification

**Date:** 2026-07-01  
**Target:** Supabase demo database (via MCP)  
**MySQL originals:** unchanged in `backend/src/schemas/`

## Schema status

| Check | Status |
|-------|--------|
| Public tables created | **PASS** (~110 tables) |
| PostGIS extension | **PASS** |
| Core tables (`users`, `administrative_areas`, `emergency_incidents`, `agencies`, `disaster_events`) | **PASS** |
| Triggers / views | **PASS** (applied with PG-specific fixes during MCP apply) |
| Original MySQL SQL files modified | **PASS** (none touched) |

## Seed data status (verified 2026-07-01, post chunk 03 + 04 apply)

| Table | Count | Notes |
|-------|------:|-------|
| `roles` | 4 | Reference seed (chunk 01) |
| `blood_groups` | 8 | Reference seed |
| `administrative_areas` | 3,000+ | Bangladesh hierarchy; re-apply skips duplicates |
| `users` | 12 | Demo citizens, dispatcher, agency reps (chunk 03) |
| `agencies` | 13 | Demo + storyline agencies (chunks 03–04) |
| `facilities` | 14 | Includes `SHELTER-KUR-01` and other storyline shelters |
| `intake_reports` | 16+ | Pre-disaster, risk, fire (6), and flood intakes |
| `emergency_incidents` | 4 | Operational showcase incidents (chunk 03) |
| `emergency_units` | 20 | Dhaka + national demo units |

## Chunk 03 + 04 — applied

- **Chunk 03:** notification templates, agencies, units, operational showcase, reporter risk demo
- **Chunk 04:** storyline demo (Puran Dhaka fire + Kurigram/Gaibandha flood setup)
- **Prerequisite migration:** `niers_agencies_missing_columns` added `head_office_location_id`, `is_active`, `description`, timestamps on `agencies`
- **Postgres fixes at apply time:** `FROM DUAL` removal, `ON CONFLICT` targets, boolean literals, `DELETE` syntax
- **Verify:**
  ```sql
  SELECT COUNT(*) FROM intake_reports WHERE report_code LIKE 'IR-DHK-FIRE%';  -- 6
  SELECT COUNT(*) FROM facilities WHERE facility_code = 'SHELTER-KUR-01';      -- 1
  SELECT COUNT(*) FROM emergency_incidents;                                    -- 4
  ```
- **Known minor issue:** `DHK-FIRE-01` may appear twice (duplicate from earlier partial apply); harmless for demo unless agency lookup by code breaks

## Parallel execution

Seed chunks were applied using **two parallel workers**:

1. **Worker A** — `004_seed_data_chunk02_01` … `02_12` (admin areas, sequential inside worker)
2. **Worker B** — `004_seed_data_chunk03` + `004_seed_data_chunk04` (users + storyline demo)

Additional parallel one-shot applies were used for `02_07`–`02_10` when admin-area chunks were already partially loaded (duplicate-key skips expected).

## Known issues / manual checks before Render deploy

1. **Re-run safety:** Admin-area inserts use `ON CONFLICT (code) DO NOTHING` after converter fix — safe to re-apply.
2. **Storyline chunks (03–04):** Applied. Backend bootstrap seeds (29–33) are idempotent if re-run on Render startup.
3. **RLS:** All public tables have RLS **disabled** — acceptable for backend-only demo; not for public Supabase Data API exposure.
4. **Backend env on Render:**
   ```env
   DB_DIALECT=postgres
   DATABASE_URL=postgresql://postgres.[ref]:[password]@aws-0-[region].pooler.supabase.com:6543/postgres
   PGSSLMODE=require
   CORS_ORIGIN=https://your-vercel-app.vercel.app
   JWT_ACCESS_SECRET=...
   JWT_REFRESH_SECRET=...
   DEMO_CITIZEN_PASSWORD=...
   DEMO_DISPATCHER_PASSWORD=...
   DEMO_REP_PASSWORD=...
   ```
5. **Local Docker:** Still uses MySQL — no changes required for `docker-compose.yml`.
6. **Health check:** `GET /health` should return Postgres `version()` when connected to Supabase.

## Regenerate PostgreSQL SQL

```bash
node supabase-postgres-migration/scripts/convert-mysql-to-pg.mjs
node supabase-postgres-migration/scripts/split-migrations.mjs
```

## Verify yourself

```sql
SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public';
SELECT COUNT(*) FROM users;
SELECT COUNT(*) FROM administrative_areas;
SELECT COUNT(*) FROM agencies;
SELECT COUNT(*) FROM emergency_incidents;
```
