# SQL schema fragments (`docker-init/`)

The canonical database definition for Docker and fresh installs lives in **`docker-init/`** as ordered fragments:

1. `00_`–`04_` — session settings, drop views/triggers/tables, re-enable foreign keys  
2. `05_`–`18_` — `CREATE TABLE` DDL by domain (identity, geography, intake, … audit)  
3. `19_`–`20_` — triggers, then views  
4. `21_` — reference data seeds (roles, permissions, channels, …)  
5. `22_` — Bangladesh `administrative_areas` hierarchy (from [nuhil/bangladesh-geocode](https://github.com/nuhil/bangladesh-geocode), MIT)

The official MySQL image executes `/docker-entrypoint-initdb.d/*.sql` in **lexical** order; filenames use two-digit prefixes so sort order matches dependency order.

The former monolithic `schema.sql` has been removed; use this directory only.
