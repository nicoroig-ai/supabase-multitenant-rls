-- Two tenants, one user each, plus a user who belongs to both. Enough shape to
-- prove isolation without a fixture framework.

insert into auth.users (id, email) values
  ('11111111-1111-1111-1111-111111111111', 'alice@acme.test'),
  ('22222222-2222-2222-2222-222222222222', 'bob@globex.test'),
  ('33333333-3333-3333-3333-333333333333', 'carol@consultant.test');

insert into public.tenants (id, slug, name) values
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'acme', 'Acme'),
  ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'globex', 'Globex');

insert into public.tenant_users (tenant_id, user_id, role) values
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '11111111-1111-1111-1111-111111111111', 'owner'),
  ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', '22222222-2222-2222-2222-222222222222', 'owner'),
  -- Carol works for both. Isolation must hold per tenant, not per user.
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '33333333-3333-3333-3333-333333333333', 'member'),
  ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', '33333333-3333-3333-3333-333333333333', 'member');

insert into public.tenant_secrets (tenant_id, kind, token) values
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'whatsapp', 'acme-token-must-never-leak'),
  ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'whatsapp', 'globex-token-must-never-leak');

insert into public.contacts (id, tenant_id, full_name, email) values
  ('c0000001-0000-0000-0000-000000000001', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'Acme Lead One', 'one@acme.test'),
  ('c0000002-0000-0000-0000-000000000002', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'Acme Lead Two', 'two@acme.test'),
  ('c0000003-0000-0000-0000-000000000003', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'Globex Lead', 'lead@globex.test');

insert into public.notes (tenant_id, contact_id, body) values
  ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', 'c0000001-0000-0000-0000-000000000001', 'Called on Tuesday.'),
  ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb', 'c0000003-0000-0000-0000-000000000003', 'Asked for pricing.');
