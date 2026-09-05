# supabase-multitenant-rls

Pool multi-tenancy on Supabase/Postgres, where isolation is enforced by **Row Level Security** instead of by application code remembering to add `where tenant_id = ?` — and **18 tests that prove it holds**, run against a real Postgres in CI.

One migration, one shim, one test file. Read them in that order.

```
supabase/migrations/0001_multitenant_core.sql   the schema and the policies
test/00_shim_auth.sql                           makes it runnable on plain Postgres
test/isolation.test.mjs                         the proof
```

## The model

**Pool**: one codebase, one database, every tenant's rows side by side, each carrying a `tenant_id`. Cheap to run and to migrate. The obvious objection — "one bad query and customer A reads customer B" — is answered by moving the check into Postgres, below the application, where forgetting it is not possible.

Two roles do the work:

| Role | Who uses it | What RLS does |
|---|---|---|
| `authenticated` | the user-facing app, carrying an end user's JWT | confines every query to the tenants that user belongs to |
| `service_role` | the backend engine: webhooks, jobs, integrations | **bypasses RLS entirely** — cross-tenant by design |

Which reduces the security boundary to one sentence: *never let a `service_role` key reach a browser.* Everything else the database enforces.

## The three things worth stealing

### 1. The membership helper must be `SECURITY DEFINER`

```sql
create or replace function public.is_tenant_member(t uuid)
returns boolean
language sql stable security definer
set search_path = public, pg_temp
as $$ select exists (select 1 from public.tenant_users tu
                     where tu.tenant_id = t and tu.user_id = auth.uid()); $$;
```

This is not an optimisation. A policy on `tenant_users` that asks "is the caller a member of this tenant?" reads `tenant_users`, which fires that same policy, which reads `tenant_users`. Postgres catches it and kills the query:

```
ERROR: infinite recursion detected in policy for relation "tenant_users"  (42P17)
```

Running the lookup as the function owner takes it outside RLS and breaks the cycle. `stable` lets the planner call it once per query rather than once per row. The pinned `search_path` is mandatory for any `SECURITY DEFINER` function — without it, a caller-controlled path can decide what `tenant_users` resolves to.

### 2. Default-deny is the *absence* of a policy

```sql
alter table public.tenant_secrets enable row level security;
-- and then no policy for `authenticated`, on purpose
```

A table with RLS enabled and no matching policy returns zero rows and rejects every write. That is the entire protection for the credentials table — no clever predicate to review, nothing to get subtly wrong. `service_role` has `BYPASSRLS`, so the engine still reads the tokens it needs.

The migration also declines to `GRANT` anything on that table. Belt and braces: a table nobody can reach is a smaller target than one protected by a policy somebody might edit.

The mirror image is worth knowing too: **`BYPASSRLS` is not a privilege**. It lets `service_role` skip the policies; it does not let it reach a table it was never granted. A hosted Supabase project grants the public schema to `service_role` by default, so a migration that relies on that silently stops working the first time it runs anywhere else. This one grants explicitly — a fact CI discovered on the first run, by failing.

### 3. `USING` without `WITH CHECK` is a silent cross-tenant write

```sql
create policy contacts_tenant_isolation on public.contacts
  for all to authenticated
  using (public.is_tenant_member(tenant_id))
  with check (public.is_tenant_member(tenant_id));
```

`USING` filters the rows you can read, update or delete. `WITH CHECK` validates the rows you try to write. With `USING` alone, a member of tenant A can insert a row stamped `tenant_id = B`: the insert succeeds, the row lands in another customer's data, and the author never sees it again because `USING` hides it. No error, no trace.

The same gap lets an `UPDATE` move an existing row into another tenant. Both cases are tested.

Policies for ordinary tenant-scoped tables are applied in a loop rather than written out per table, so a new table cannot quietly ship with a hand-written variation of the rule.

## Running the tests

They need a Postgres. Nothing is mocked — the point is that the *database* enforces isolation, so anything less proves nothing.

```bash
npm install
npm run db:up                 # docker run postgres:16 on :5432
npm test
npm run db:down
```

Against your own database:

```bash
DATABASE_URL=postgres://user:pass@host:5432/db npm test
```

The suite drops and recreates its tables on each run, so point it at a scratch database, never a real one.

`test/00_shim_auth.sql` recreates just enough of Supabase — the `auth` schema, `auth.uid()`, and the two roles — for the real migration to run unmodified on a stock `postgres:16`. That is what lets CI prove the policies without a Supabase project. Never apply the shim to a Supabase database; it already has all of it.

## What the tests cover

- Reads are confined to the caller's tenants — including by primary key, and including `count(*)`, which otherwise leaks the existence of rows you cannot see.
- A user belonging to two tenants sees both and nothing more.
- Cross-tenant `INSERT` is rejected; cross-tenant `UPDATE` and `DELETE` affect zero rows.
- A row cannot be moved to another tenant by rewriting its `tenant_id`.
- The credentials table is unreachable from `authenticated`, including for the caller's *own* tenant, while `service_role` still reads it.
- Listing teammates works rather than aborting with `42P17` — the recursion case.
- An unauthenticated session (`auth.uid()` is null) sees nothing.

## When to use something else

Pool RLS is the right default. It stops being right when a customer's contract requires physical separation, or when one tenant's volume distorts the shared tables. The escape hatch is a **silo**: the same migration applied to its own Postgres project, same application code, a different connection string. Keeping the schema identical is what makes that a configuration change rather than a fork.

## License

MIT
