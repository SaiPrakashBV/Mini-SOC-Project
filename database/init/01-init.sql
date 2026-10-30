-- Runs once, the first time the PostgreSQL volume is initialised.
-- The incident schema itself is owned and migrated by the incident-tracker
-- service (Flyway, see incident-tracker/src/main/resources/db/migration).

-- Read-only role for reporting / BI tools. LOGIN is granted separately with a
-- password supplied out-of-band, e.g.:
--   ALTER ROLE soc_readonly WITH LOGIN PASSWORD '...';
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'soc_readonly') THEN
        CREATE ROLE soc_readonly NOLOGIN;
    END IF;
END
$$;

DO $$
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO soc_readonly', current_database());
END
$$;
GRANT USAGE ON SCHEMA public TO soc_readonly;
-- Tables are created later by Flyway (as the application user); make sure the
-- reporting role can read them.
ALTER DEFAULT PRIVILEGES FOR ROLE CURRENT_USER IN SCHEMA public GRANT SELECT ON TABLES TO soc_readonly;
