# NIERS backend

## Database (Docker)

MySQL 8 is defined in [docker-compose.yml](docker-compose.yml). On **first start** with an **empty** data volume, the image runs every `*.sql` file in [src/schemas/docker-init/](src/schemas/docker-init/) in **lexical order** (see [src/schemas/README.md](src/schemas/README.md)).

```bash
cd backend
docker compose up --build
```

After changing any file under `src/schemas/docker-init/`, reset the DB volume so init runs again:

```bash
docker compose down -v
docker compose up --build
```

### Regenerating administrative areas (maintainers only)

Bangladesh admin hierarchy is committed as `docker-init/22_seed_administrative_areas.sql`. To refresh from upstream JSON (requires network):

```bash
# from repository root
npm run generate:admin-areas
```

Source and license: [third_party/bangladesh-geocode/README.md](third_party/bangladesh-geocode/README.md).

### Optional: Barikoi API key

GPS-based `admin_area_id` resolution uses Barikoi when `BARIKOI_API_KEY` is set. See [docs/backend-external-dependencies.md](../docs/backend-external-dependencies.md).

## Demo accounts

Seeded on server start when `backend/.env` is configured. See [docs/demo-accounts.md](../docs/demo-accounts.md) for emails, roles, and password env vars.

## Testing

From the repository root:

```bash
# Fast contract + unit tests (no MySQL required)
npm test

# Full HTTP smoke tests against Docker MySQL + backend/.env
npm run test:integration
```

**Integration prerequisites**

- MySQL running (`cd backend && docker compose up`)
- [`backend/.env`](.env) with `MYSQL_*`, `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`
- `SYSTEM_ADMIN__EMAIL` / `SYSTEM_ADMIN_PASSWORD` for admin/operations smoke tests
- `DEMO_REP_PASSWORD` for agency rep smoke tests (`fire.rep@niers.test` seed user)
- `DEMO_DISPATCHER_PASSWORD` for dispatcher smoke tests (`dispatcher@niers.test` seed user)

Optional: `npm run test:barikoi-live` exercises the real Barikoi API when `BARIKOI_API_KEY` is set.
