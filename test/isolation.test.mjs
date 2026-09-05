/**
 * Isolation tests.
 *
 * These are the tests that matter. A multi-tenant schema whose isolation is
 * never executed is a claim, not a guarantee — and the failure mode is not a
 * crash, it is one customer quietly reading another customer's data.
 *
 * Every case runs inside a transaction that assumes an end user's identity the
 * same way PostgREST does: set the JWT claims GUC, then `set local role
 * authenticated`. Nothing here trusts application code to filter anything.
 */

import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import pg from "pg";

const here = dirname(fileURLToPath(import.meta.url));
const CONNECTION =
  process.env.DATABASE_URL ?? "postgres://postgres:postgres@localhost:5432/postgres";

const ALICE = "11111111-1111-1111-1111-111111111111"; // Acme only
const BOB = "22222222-2222-2222-2222-222222222222"; // Globex only
const CAROL = "33333333-3333-3333-3333-333333333333"; // both
const ACME = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa";
const GLOBEX = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb";

/** @type {pg.Client} */
let db;

before(async () => {
  db = new pg.Client({ connectionString: CONNECTION });
  await db.connect();
  const files = [
    join(here, "00_shim_auth.sql"),
    join(here, "..", "supabase", "migrations", "0001_multitenant_core.sql"),
    join(here, "02_seed.sql"),
  ];
  // Start from a clean slate so the suite is re-runnable against a live database.
  await db.query(`
    drop table if exists public.notes, public.contacts, public.tenant_secrets,
      public.tenant_users, public.tenants cascade;
    drop function if exists public.is_tenant_member(uuid);
    drop table if exists auth.users cascade;
  `);
  for (const f of files) await db.query(readFileSync(f, "utf8"));
});

after(async () => {
  await db?.end();
});

/**
 * Run a callback as an end user: JWT claims set, role downgraded to
 * `authenticated`, everything rolled back afterwards so tests stay independent.
 */
async function asUser(userId, fn) {
  await db.query("begin");
  try {
    await db.query("select set_config('request.jwt.claims', $1, true)", [
      JSON.stringify({ sub: userId, role: "authenticated" }),
    ]);
    await db.query("set local role authenticated");
    return await fn();
  } finally {
    await db.query("rollback");
  }
}

/** Same, as the backend engine. */
async function asServiceRole(fn) {
  await db.query("begin");
  try {
    await db.query("set local role service_role");
    return await fn();
  } finally {
    await db.query("rollback");
  }
}

const rows = async (sql, params) => (await db.query(sql, params)).rows;

describe("reads are confined to the caller's tenants", () => {
  test("a user sees only their own tenant's contacts", async () => {
    await asUser(ALICE, async () => {
      const r = await rows("select tenant_id, full_name from public.contacts");
      assert.equal(r.length, 2);
      assert.ok(r.every((c) => c.tenant_id === ACME));
    });
  });

  test("the other tenant's rows are invisible, not merely unlisted", async () => {
    await asUser(ALICE, async () => {
      // Asking for a row by primary key must also come back empty. A filter
      // applied only in application code would happily return this.
      const r = await rows("select * from public.contacts where id = $1", [
        "c0000003-0000-0000-0000-000000000003",
      ]);
      assert.equal(r.length, 0);
    });
  });

  test("count(*) does not leak the existence of other tenants' rows", async () => {
    await asUser(BOB, async () => {
      const r = await rows("select count(*)::int as n from public.contacts");
      assert.equal(r[0].n, 1);
    });
  });

  test("a user in two tenants sees both, and nothing else", async () => {
    await asUser(CAROL, async () => {
      const r = await rows("select distinct tenant_id from public.contacts order by tenant_id");
      assert.deepEqual(
        r.map((x) => x.tenant_id),
        [ACME, GLOBEX],
      );
    });
  });

  test("the tenant list itself is filtered by membership", async () => {
    await asUser(ALICE, async () => {
      const r = await rows("select slug from public.tenants");
      assert.deepEqual(
        r.map((t) => t.slug),
        ["acme"],
      );
    });
  });
});

describe("writes cannot cross a tenant boundary", () => {
  test("inserting into another tenant is rejected by WITH CHECK", async () => {
    await asUser(ALICE, async () => {
      await assert.rejects(
        () =>
          db.query(
            "insert into public.contacts (tenant_id, full_name) values ($1, $2)",
            [GLOBEX, "smuggled"],
          ),
        (err) => {
          // 42501 = insufficient_privilege, raised by the policy.
          assert.equal(err.code, "42501");
          return true;
        },
      );
    });
  });

  test("inserting into your own tenant works", async () => {
    await asUser(ALICE, async () => {
      const r = await rows(
        "insert into public.contacts (tenant_id, full_name) values ($1, $2) returning id",
        [ACME, "legitimate"],
      );
      assert.equal(r.length, 1);
    });
  });

  test("updating another tenant's row affects nothing", async () => {
    await asUser(ALICE, async () => {
      const res = await db.query("update public.contacts set full_name = $1 where id = $2", [
        "hijacked",
        "c0000003-0000-0000-0000-000000000003",
      ]);
      // No error, no rows: USING hid the row before UPDATE ever saw it.
      assert.equal(res.rowCount, 0);
    });
  });

  test("deleting another tenant's row affects nothing", async () => {
    await asUser(BOB, async () => {
      const res = await db.query("delete from public.contacts where tenant_id = $1", [ACME]);
      assert.equal(res.rowCount, 0);
    });
  });

  test("a row cannot be moved to another tenant by UPDATE", async () => {
    await asUser(ALICE, async () => {
      // The escape hatch people forget: USING lets you touch your own row,
      // WITH CHECK is what stops you rewriting its tenant_id to someone else's.
      await assert.rejects(
        () =>
          db.query("update public.contacts set tenant_id = $1 where id = $2", [
            GLOBEX,
            "c0000001-0000-0000-0000-000000000001",
          ]),
        (err) => {
          assert.equal(err.code, "42501");
          return true;
        },
      );
    });
  });
});

describe("secrets are unreachable from the user-facing role", () => {
  test("selecting credentials fails outright", async () => {
    await asUser(ALICE, async () => {
      await assert.rejects(
        () => db.query("select token from public.tenant_secrets"),
        (err) => {
          // No GRANT at all, so this never even reaches the policy layer.
          assert.equal(err.code, "42501");
          return true;
        },
      );
    });
  });

  test("even the tenant's own credentials stay out of reach", async () => {
    await asUser(ALICE, async () => {
      await assert.rejects(() =>
        db.query("select token from public.tenant_secrets where tenant_id = $1", [ACME]),
      );
    });
  });

  test("the engine can still read them", async () => {
    await asServiceRole(async () => {
      const r = await rows("select tenant_id, token from public.tenant_secrets order by token");
      assert.equal(r.length, 2);
    });
  });
});

describe("the membership helper does not recurse", () => {
  test("listing teammates works instead of aborting the query", async () => {
    // Without SECURITY DEFINER on is_tenant_member, this policy reads
    // tenant_users, which fires this policy, which reads tenant_users:
    // Postgres raises 42P17 'infinite recursion detected in policy'.
    await asUser(CAROL, async () => {
      const r = await rows("select tenant_id, user_id from public.tenant_users");
      assert.equal(r.length, 4); // 2 members in Acme + 2 in Globex
    });
  });

  test("a non-member's tenants are still hidden", async () => {
    await asUser(ALICE, async () => {
      const r = await rows("select distinct tenant_id from public.tenant_users");
      assert.deepEqual(
        r.map((x) => x.tenant_id),
        [ACME],
      );
    });
  });
});

describe("service_role is the deliberate escape hatch", () => {
  test("it sees every tenant, which is why its key must stay server-side", async () => {
    await asServiceRole(async () => {
      const r = await rows("select count(*)::int as n from public.contacts");
      assert.equal(r[0].n, 3);
    });
  });

  test("it can write on any tenant's behalf", async () => {
    await asServiceRole(async () => {
      const r = await rows(
        "insert into public.notes (tenant_id, body) values ($1, $2) returning id",
        [GLOBEX, "written by the engine"],
      );
      assert.equal(r.length, 1);
    });
  });
});

describe("anonymous access", () => {
  test("an unauthenticated session sees nothing", async () => {
    // auth.uid() returns null, so is_tenant_member() is false everywhere.
    await db.query("begin");
    try {
      await db.query("set local role authenticated");
      const r = (await db.query("select * from public.contacts")).rows;
      assert.equal(r.length, 0);
    } finally {
      await db.query("rollback");
    }
  });
});
