-- ============================================================================
-- Multi-tenant core: pool model with Row Level Security.
--
-- One codebase, one database, every tenant's rows side by side, isolation
-- enforced by Postgres rather than by application code remembering to add
-- `where tenant_id = ?` to every query.
--
-- Two roles do the work:
--
--   authenticated  -- the user-facing app, carrying an end user's JWT.
--                     RLS confines it to the tenants that user belongs to.
--   service_role   -- the backend engine: webhooks, jobs, integrations.
--                     Has BYPASSRLS. Runs cross-tenant on purpose.
--
-- The security boundary is therefore: never hand a service_role key to
-- anything that runs in a browser. Everything else the database enforces.
-- ============================================================================

create extension if not exists pgcrypto; -- gen_random_uuid()

-- ---------------------------------------------------------------------------
-- Tables
-- ---------------------------------------------------------------------------

create table if not exists public.tenants (
  id         uuid primary key default gen_random_uuid(),
  slug       text not null unique,
  name       text not null,
  status     text not null default 'active'
               check (status in ('active', 'paused', 'archived')),
  created_at timestamptz not null default now()
);

-- Membership is the single source of truth for "who may see what". Every
-- policy in this file reduces to a lookup against this table.
create table if not exists public.tenant_users (
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  user_id   uuid not null references auth.users(id) on delete cascade,
  role      text not null default 'member'
              check (role in ('owner', 'admin', 'member')),
  primary key (tenant_id, user_id)
);

create index if not exists tenant_users_user_idx on public.tenant_users (user_id);

-- Third-party credentials, per tenant. Deliberately has NO policy for
-- `authenticated` -- see the RLS section below.
create table if not exists public.tenant_secrets (
  id         uuid primary key default gen_random_uuid(),
  tenant_id  uuid not null references public.tenants(id) on delete cascade,
  kind       text not null,
  token      text not null,
  created_at timestamptz not null default now(),
  unique (tenant_id, kind)
);

-- Two ordinary tenant-scoped tables, standing in for the rest of a real
-- schema. Both follow the same rule: tenant_id not null, isolated by policy.
create table if not exists public.contacts (
  id         uuid primary key default gen_random_uuid(),
  tenant_id  uuid not null references public.tenants(id) on delete cascade,
  full_name  text not null,
  email      text,
  created_at timestamptz not null default now()
);

create index if not exists contacts_tenant_idx on public.contacts (tenant_id);

create table if not exists public.notes (
  id         uuid primary key default gen_random_uuid(),
  tenant_id  uuid not null references public.tenants(id) on delete cascade,
  contact_id uuid references public.contacts(id) on delete cascade,
  body       text not null,
  created_at timestamptz not null default now()
);

create index if not exists notes_tenant_idx on public.notes (tenant_id);

-- ---------------------------------------------------------------------------
-- Membership helper
-- ---------------------------------------------------------------------------
--
-- SECURITY DEFINER is not an optimisation here, it is what makes the policies
-- terminate. A policy on tenant_users that asks "is the caller a member of
-- this tenant?" has to read tenant_users -- which fires that same policy --
-- which reads tenant_users. Postgres detects it and aborts the query with
-- "infinite recursion detected in policy for relation tenant_users".
--
-- Running the lookup as the function owner takes it outside RLS and breaks
-- the cycle. STABLE lets the planner call it once per query instead of once
-- per row. The pinned search_path stops a caller-controlled path from
-- resolving `tenant_users` to something else -- mandatory for any
-- SECURITY DEFINER function.
create or replace function public.is_tenant_member(t uuid)
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1
    from public.tenant_users tu
    where tu.tenant_id = t
      and tu.user_id = auth.uid()
  );
$$;

revoke all on function public.is_tenant_member(uuid) from public;
grant execute on function public.is_tenant_member(uuid) to authenticated;

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------
--
-- RLS filters what a role can already reach through GRANT; it never adds
-- access. Grant first, then constrain with policies.
grant usage on schema public to authenticated;
grant select on public.tenants to authenticated;
grant select on public.tenant_users to authenticated;
grant select, insert, update, delete on public.contacts to authenticated;
grant select, insert, update, delete on public.notes to authenticated;

-- Note what is missing: no grant on tenant_secrets. Belt and braces -- the
-- deny-all policy below would stop it anyway, but a table nobody can reach is
-- a smaller target than one protected by a policy somebody might edit.

-- BYPASSRLS is not a privilege. It lets service_role skip the policies; it
-- does not let it reach a table it was never granted. A hosted Supabase
-- project already grants the public schema to service_role by default, so this
-- gap only shows up the first time the schema runs somewhere else -- which is
-- a poor moment to discover it. Grant explicitly and stay portable.
grant usage on schema public to service_role;
grant all privileges on all tables in schema public to service_role;
grant all privileges on all sequences in schema public to service_role;

-- And for tables added by later migrations.
alter default privileges in schema public grant all on tables to service_role;
alter default privileges in schema public grant all on sequences to service_role;

-- ---------------------------------------------------------------------------
-- Row Level Security
-- ---------------------------------------------------------------------------

-- tenants: you see the tenants you belong to.
alter table public.tenants enable row level security;
drop policy if exists tenants_member_select on public.tenants;
create policy tenants_member_select on public.tenants
  for select to authenticated
  using (public.is_tenant_member(id));

-- tenant_users: you see every member of your own tenants -- a teammate list.
-- This is the policy that would recurse without a SECURITY DEFINER helper.
alter table public.tenant_users enable row level security;
drop policy if exists tenant_users_same_tenant on public.tenant_users;
create policy tenant_users_same_tenant on public.tenant_users
  for select to authenticated
  using (public.is_tenant_member(tenant_id));

-- tenant_secrets: RLS enabled, and deliberately no policy for `authenticated`.
-- A table with RLS on and no matching policy returns zero rows and rejects
-- every write. service_role has BYPASSRLS, so the engine still reads tokens.
--
-- This is the one pattern worth internalising: default-deny is the absence of
-- a policy, not the presence of a clever one.
alter table public.tenant_secrets enable row level security;

-- Ordinary tenant-scoped tables: identical isolation, applied in a loop so a
-- new table cannot quietly ship with a hand-written variation of the rule.
do $$
declare
  tbl text;
begin
  foreach tbl in array array['contacts', 'notes'] loop
    execute format('alter table public.%I enable row level security;', tbl);
    execute format('drop policy if exists %I on public.%I;',
                   tbl || '_tenant_isolation', tbl);
    execute format(
      'create policy %I on public.%I
         for all to authenticated
         using (public.is_tenant_member(tenant_id))
         with check (public.is_tenant_member(tenant_id));',
      tbl || '_tenant_isolation', tbl);
  end loop;
end $$;

-- USING filters the rows you can read, update or delete.
-- WITH CHECK validates the rows you try to write.
--
-- Both are required. With USING alone, a member of tenant A can INSERT a row
-- stamped tenant_id = B: the insert succeeds, the row lands in another
-- tenant's data, and the author never sees it again because USING hides it.
-- Silent cross-tenant write, no error, no trace.
