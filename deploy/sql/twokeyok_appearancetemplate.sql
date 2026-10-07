-- TwoKeyOk MiddleWare Orchestrator — appearance template table
--
-- Used when signing.dss.signature.appearance.store is jdbc. Same structure as
-- the Ascertia Orchestrator's appearancetemplate table, but a table of its own,
-- so neither product can change the other's templates.
--
-- Run as a role allowed to create tables in the database, e.g.:
--   sudo -u postgres psql -d orchestrator_eseal -f deploy/sql/twokeyok_appearancetemplate.sql
--
-- The orchestrator never creates or alters this table itself. Its account needs
-- only the four privileges granted at the end. Safe to run again.

CREATE TABLE IF NOT EXISTS public.twokeyok_appearancetemplate (
    template_id         varchar(255) NOT NULL PRIMARY KEY,
    signatureappearance text
);

COMMENT ON TABLE public.twokeyok_appearancetemplate IS
    'Signature appearance templates of the TwoKeyOk MiddleWare Orchestrator (Ascertia JSON shape)';

-- The orchestrator's own login. Set its password afterwards with:
--   sudo -u postgres psql -c "\password twokeyok_appearance"
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'twokeyok_appearance') THEN
        CREATE ROLE twokeyok_appearance LOGIN;
    END IF;
END
$$;

GRANT CONNECT ON DATABASE orchestrator_eseal TO twokeyok_appearance;
GRANT USAGE ON SCHEMA public TO twokeyok_appearance;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.twokeyok_appearancetemplate TO twokeyok_appearance;

-- Isolation is enforced here, not just configured: whatever was granted on the
-- Ascertia Orchestrator's own table to this login is taken back.
DO $$
BEGIN
    IF to_regclass('public.appearancetemplate') IS NOT NULL THEN
        REVOKE ALL ON public.appearancetemplate FROM twokeyok_appearance;
    END IF;
END
$$;
