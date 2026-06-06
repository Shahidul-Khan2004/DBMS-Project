# SQL schema fragments (`docker-init/`)

The canonical database definition for Docker and fresh installs lives in **`docker-init/`** as ordered fragments:

1. `00_`–`04_` — session settings, drop views/triggers/tables, re-enable foreign keys  
2. `05_`–`18_` — `CREATE TABLE` DDL by domain (identity, geography, intake, … audit)  
3. `19_`–`20_` — triggers, then views  
4. `21_` — reference data seeds (roles, permissions, channels, …)  
5. `22_` — Bangladesh `administrative_areas` hierarchy (from [nuhil/bangladesh-geocode](https://github.com/nuhil/bangladesh-geocode), MIT); emitted as **4 bulk inserts** (one per level) for fast Docker init  
6. `24_`–`28_` — demo agencies, Dhaka/Kurigram master data, agency-rep incident  
7. `29_`–`31_` — **showcase operational demo** (citizen locations, day-to-day intakes/incidents, case messages)  
8. `27_` — adds `agency_memberships.public_uuid` on DBs created before that column existed (also applied automatically on server bootstrap)

The official MySQL image executes `/docker-entrypoint-initdb.d/*.sql` in **lexical** order; filenames use two-digit prefixes so sort order matches dependency order.

**Showcase seeds (`29`–`31`):** On first Docker init, user-dependent rows are skipped (demo citizens do not exist yet). On backend startup, [`operationalDemoSeedService.js`](../services/operationalDemoSeedService.js) re-runs these files after [`demoCitizenBootstrapService.js`](../services/demoCitizenBootstrapService.js) creates citizens. All inserts are idempotent.

The former monolithic `schema.sql` has been removed; use this directory only.
