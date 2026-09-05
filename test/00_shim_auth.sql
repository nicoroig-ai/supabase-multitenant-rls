-- ============================================================================
-- Supabase compatibility shim -- FOR LOCAL AND CI TESTING ONLY.
--
-- A hosted Supabase project already provides the `auth` schema, `auth.uid()`
-- and the authenticated / service_role database roles. Plain Postgres does
-- not. This file recreates just enough of them that the real migration runs
-- unmodified against a stock `postgres:16` container, so the policies can be
-- proven in CI without a Supabase project.
--
-- Never apply this to a Supabase database.
-- ============================================================================

create extension if not exists pgcrypto;
create schema if not exists auth;

create table if not exists auth.users (
  id    uuid primary key default gen_random_uuid(),
  email text unique
);

-- Same definition Supabase uses: read the subject claim out of the JWT that
-- PostgREST puts into the session as a GUC.
create or replace function auth.uid()
returns uuid
language sql
stable
as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid
$$;

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then
    create role authenticated nologin;
  end if;
  -- BYPASSRLS is the whole point of service_role: the backend engine reads and
  -- writes across every tenant, which is exactly why its key must never reach
  -- a browser.
  if not exists (select 1 from pg_roles where rolname = 'service_role') then
    create role service_role nologin bypassrls;
  end if;
end $$;

grant usage on schema auth to authenticated, service_role;
grant execute on function auth.uid() to authenticated, service_role;
