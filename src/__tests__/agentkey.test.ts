import { describe, it, expect, beforeAll, afterAll } from "vitest";
import pg from "pg";
import express from "express";
import type { Server } from "http";
import { AgentKey, createAgentKeyRoutes, agentKeyMiddleware } from "../index.js";

const TEST_DB =
  process.env.DATABASE_URL ??
  "postgres://postgres:postgres@localhost:5432/postgres";

let pool: pg.Pool;
let ak: AgentKey;

beforeAll(async () => {
  pool = new pg.Pool({ connectionString: TEST_DB });

  await pool.query(`
    CREATE TABLE IF NOT EXISTS sdk_api_keys (
      id SERIAL PRIMARY KEY,
      account_id TEXT,
      key_hash TEXT NOT NULL UNIQUE,
      key_prefix TEXT NOT NULL,
      name TEXT NOT NULL DEFAULT 'default',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      last_used_at TIMESTAMPTZ,
      revoked_at TIMESTAMPTZ
    )
  `);

  ak = new AgentKey({
    pool,
    keyPrefix: "test_",
    validScopes: ["read", "write", "admin"],
  });

  await ak.migrate();
});

afterAll(async () => {
  await pool.query("DELETE FROM sdk_api_keys WHERE key_prefix LIKE 'test_%'");
  await pool.end();
});

describe("create", () => {
  it("creates a key with scopes and budget", async () => {
    const result = await ak.create({
      accountId: "acct_test_1",
      scopes: ["read"],
      budgetCents: 1000,
      budgetPeriod: "month",
      expiresIn: "1d",
      name: "test-key",
    });

    expect(result.key).toMatch(/^test_/);
    expect(result.id).toBeGreaterThan(0);
    expect(result.scopes).toEqual(["read"]);
    expect(result.budgetCents).toBe(1000);
    expect(result.expiresAt).toBeTruthy();
  });

  it("creates a key with no scopes (unlimited)", async () => {
    const result = await ak.create({ accountId: "acct_test_2" });
    expect(result.scopes).toBeNull();
    expect(result.budgetCents).toBeNull();
  });

  it("rejects invalid scopes", async () => {
    await expect(
      ak.create({ accountId: "acct_test_3", scopes: ["fake_scope"] }),
    ).rejects.toThrow("Invalid scopes: fake_scope");
  });

  // Regression: "m" used to silently mean months, minting keys ~43000x
  // longer-lived than a developer expecting minutes intended. Found by /qa
  // on 2026-06-18.
  it("treats expiresIn 'm' as minutes and 'mo' as months", async () => {
    const minutes = await ak.create({ accountId: "acct_dur_m", expiresIn: "5m" });
    const minDelta = new Date(minutes.expiresAt!).getTime() - Date.now();
    expect(Math.round(minDelta / 60000)).toBe(5);

    const months = await ak.create({ accountId: "acct_dur_mo", expiresIn: "1mo" });
    const moDelta = new Date(months.expiresAt!).getTime() - Date.now();
    expect(Math.round(moDelta / 86400000)).toBe(30);
  });

  it("throws on a malformed duration", async () => {
    await expect(
      ak.create({ accountId: "acct_dur_bad", expiresIn: "7days" }),
    ).rejects.toThrow("Invalid duration");
  });
});

describe("validate", () => {
  it("validates a valid key", async () => {
    const created = await ak.create({
      accountId: "acct_test_val",
      scopes: ["read", "write"],
      budgetCents: 5000,
      budgetPeriod: "month",
    });

    const result = await ak.validate(created.key);
    expect(result.valid).toBe(true);
    if (!result.valid) return;

    expect(result.scopes).toEqual(["read", "write"]);
    expect(result.budgetCents).toBe(5000);
    expect(result.budgetUsedCents).toBe(0);
    expect(result.budgetRemainingCents).toBe(5000);
  });

  it("rejects an invalid key", async () => {
    const result = await ak.validate("test_fakekeythatdoesnotexist");
    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.reason).toBe("invalid");
  });

  it("rejects a revoked key", async () => {
    const created = await ak.create({ accountId: "acct_test_revoke" });
    await ak.revoke(created.id);

    const result = await ak.validate(created.key);
    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.reason).toBe("revoked");
  });

  it("rejects an expired key", async () => {
    const created = await ak.create({
      accountId: "acct_test_expire",
      expiresIn: "0h",
    });

    // Manually set expires_at to the past
    await pool.query(
      "UPDATE sdk_api_keys SET expires_at = NOW() - INTERVAL '1 hour' WHERE id = $1",
      [created.id],
    );

    const result = await ak.validate(created.key);
    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.reason).toBe("expired");
  });

  // Regression: name was returned raw while typed non-null, so a legacy row
  // with a NULL name violated the type. Found by /qa on 2026-06-18.
  it("coalesces a null name to 'default'", async () => {
    const created = await ak.create({ accountId: "acct_null_name" });
    // Simulate a legacy table whose name column is nullable.
    await pool.query("ALTER TABLE sdk_api_keys ALTER COLUMN name DROP NOT NULL");
    await pool.query("UPDATE sdk_api_keys SET name = NULL WHERE id = $1", [
      created.id,
    ]);
    const result = await ak.validate(created.key);
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    expect(result.name).toBe("default");
  });

  // Regression: nextCalendarMonth overflowed for end-of-month dates (Jan 31 ->
  // Mar 3, skipping February and drifting to the 3rd thereafter). Found by /qa
  // on 2026-06-18.
  it("rolls a month-end reset date to a real day, not an overflow", async () => {
    const created = await ak.create({
      accountId: "acct_month_end",
      budgetCents: 100,
      budgetPeriod: "month",
    });
    // Force a reset date on the 31st, far in the past, so validate() rolls it.
    await pool.query(
      "UPDATE sdk_api_keys SET budget_reset_at = '2020-01-31T12:00:00Z' WHERE id = $1",
      [created.id],
    );
    const result = await ak.validate(created.key);
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    // Clamped to month-end (28-31). The overflow bug drifted it to the 3rd.
    const day = new Date(result.budgetResetAt!).getDate();
    expect(day).toBeGreaterThanOrEqual(28);
  });

  // Regression: budget reset never fired for an exhausted key because the
  // budget_exceeded check ran before the reset. Found by /qa on 2026-06-18.
  it("resets an exhausted budget once the period rolls over", async () => {
    const created = await ak.create({
      accountId: "acct_test_reset",
      budgetCents: 100,
      budgetPeriod: "day",
    });
    await ak.trackUsage(created.key, { costCents: 100 });

    // Within the period, the exhausted key is still blocked.
    const blocked = await ak.validate(created.key);
    expect(blocked.valid).toBe(false);
    if (blocked.valid) return;
    expect(blocked.reason).toBe("budget_exceeded");

    // Simulate several days passing.
    const stale = Date.now() - 5 * 86400000;
    await pool.query(
      "UPDATE sdk_api_keys SET budget_reset_at = NOW() - INTERVAL '5 days' WHERE id = $1",
      [created.id],
    );

    const result = await ak.validate(created.key);
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    expect(result.budgetUsedCents).toBe(0);
    expect(result.budgetRemainingCents).toBe(100);
    // Reset date must have advanced off the stale 5-days-ago value, not be
    // left in the past where it was set.
    expect(new Date(result.budgetResetAt!).getTime()).toBeGreaterThan(stale);
  });
});

describe("trackUsage", () => {
  it("tracks usage and decrements budget", async () => {
    const created = await ak.create({
      accountId: "acct_test_usage",
      budgetCents: 100,
    });

    const r1 = await ak.trackUsage(created.key, { costCents: 30 });
    expect(r1.success).toBe(true);
    expect(r1.budgetUsedCents).toBe(30);
    expect(r1.budgetRemainingCents).toBe(70);

    const r2 = await ak.trackUsage(created.key, { costCents: 50 });
    expect(r2.success).toBe(true);
    expect(r2.budgetUsedCents).toBe(80);
    expect(r2.budgetRemainingCents).toBe(20);
  });

  it("rejects when budget exceeded", async () => {
    const created = await ak.create({
      accountId: "acct_test_over",
      budgetCents: 50,
    });

    await ak.trackUsage(created.key, { costCents: 40 });
    const result = await ak.trackUsage(created.key, { costCents: 20 });
    expect(result.success).toBe(false);
    expect(result.reason).toBe("budget_exceeded");
  });

  // Regression: trackUsage ignored the period reset (only validate reset it), so
  // a charge after the period rolled over was measured against last period's
  // spend and wrongly rejected. trackUsage now resets-then-charges atomically.
  it("resets the period inside trackUsage, without a preceding validate", async () => {
    const created = await ak.create({
      accountId: "acct_track_reset",
      budgetCents: 100,
      budgetPeriod: "day",
    });
    // Exhaust this period.
    const exhausted = await ak.trackUsage(created.key, { costCents: 100 });
    expect(exhausted.success).toBe(true);
    const blocked = await ak.trackUsage(created.key, { costCents: 10 });
    expect(blocked.success).toBe(false);
    expect(blocked.reason).toBe("budget_exceeded");

    // Roll the period over, then charge again WITHOUT calling validate first.
    await pool.query(
      "UPDATE sdk_api_keys SET budget_reset_at = NOW() - INTERVAL '2 days' WHERE id = $1",
      [created.id],
    );
    const fresh = await ak.trackUsage(created.key, { costCents: 30 });
    expect(fresh.success).toBe(true);
    expect(fresh.budgetUsedCents).toBe(30);
    expect(fresh.budgetRemainingCents).toBe(70);
  });

  it("allows unlimited usage with null budget", async () => {
    const created = await ak.create({ accountId: "acct_test_unlimited" });

    const r = await ak.trackUsage(created.key, { costCents: 99999 });
    expect(r.success).toBe(true);
    expect(r.budgetRemainingCents).toBeNull();
  });

  // Regression: a non-finite costCents bypassed the <= 0 guard and the
  // budget check, then hit the DB as "NaN". Found by /qa on 2026-06-18.
  it("rejects a non-finite costCents", async () => {
    const created = await ak.create({
      accountId: "acct_test_nan",
      budgetCents: 100,
    });
    const r = await ak.trackUsage(created.key, { costCents: NaN });
    expect(r.success).toBe(false);
    expect(r.reason).toBe("invalid_cost");
  });

  // Regression: trackUsage did SELECT-then-UPDATE, so concurrent charges all
  // read the old balance and overspent the cap (a 100c budget hit 400c under
  // 20-way concurrency). Found by /qa on 2026-06-18.
  it("never overspends the budget under concurrent charges", async () => {
    const created = await ak.create({
      accountId: "acct_race",
      budgetCents: 100,
    });
    const results = await Promise.all(
      Array.from({ length: 20 }, () =>
        ak.trackUsage(created.key, { costCents: 20 }),
      ),
    );
    const succeeded = results.filter((r) => r.success).length;
    expect(succeeded).toBe(5); // exactly 100 / 20, never more

    const row = await pool.query(
      "SELECT budget_used_cents FROM sdk_api_keys WHERE id = $1",
      [created.id],
    );
    expect(row.rows[0].budget_used_cents).toBe(100);
  });
});

describe("hasScope", () => {
  it("returns true for matching scope", async () => {
    const created = await ak.create({
      accountId: "acct_test_scope",
      scopes: ["read", "write"],
    });
    const result = await ak.validate(created.key);
    if (!result.valid) throw new Error("should be valid");

    expect(ak.hasScope(result, "read")).toBe(true);
    expect(ak.hasScope(result, "write")).toBe(true);
    expect(ak.hasScope(result, "admin")).toBe(false);
  });

  it("returns true for any scope when scopes is null", async () => {
    const created = await ak.create({ accountId: "acct_test_null_scope" });
    const result = await ak.validate(created.key);
    if (!result.valid) throw new Error("should be valid");

    expect(ak.hasScope(result, "anything")).toBe(true);
  });

  it("admin scope overrides all", async () => {
    const created = await ak.create({
      accountId: "acct_test_admin",
      scopes: ["admin"],
    });
    const result = await ak.validate(created.key);
    if (!result.valid) throw new Error("should be valid");

    expect(ak.hasScope(result, "read")).toBe(true);
    expect(ak.hasScope(result, "write")).toBe(true);
    expect(ak.hasScope(result, "anything")).toBe(true);
  });
});

describe("revoke", () => {
  // Regression: revoke had no account scoping, so any key could revoke any
  // other key by ID. Found by /qa on 2026-06-18.
  it("only revokes a key the given account owns", async () => {
    const victim = await ak.create({ accountId: "acct_owner" });

    const wrongAccount = await ak.revoke(victim.id, "acct_attacker");
    expect(wrongAccount).toBe(false);
    const stillValid = await ak.validate(victim.key);
    expect(stillValid.valid).toBe(true);

    const rightAccount = await ak.revoke(victim.id, "acct_owner");
    expect(rightAccount).toBe(true);
    const nowRevoked = await ak.validate(victim.key);
    expect(nowRevoked.valid).toBe(false);
  });
});

describe("routes (security)", () => {
  let server: Server;
  let base: string;

  beforeAll(async () => {
    const app = express();
    app.use(express.json());
    app.use(createAgentKeyRoutes(ak));
    server = app.listen(0);
    const addr = server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    base = `http://localhost:${port}`;
  });

  afterAll(() => {
    server.close();
  });

  const auth = (key: string) => ({
    Authorization: `Bearer ${key}`,
    "Content-Type": "application/json",
  });

  // Regression: DELETE /sdk-keys/:id let any key revoke any other account's
  // key by guessing sequential IDs (IDOR). Found by /qa on 2026-06-18.
  it("does not let one account revoke another account's key", async () => {
    const attacker = await ak.create({
      accountId: "acct_A",
      scopes: ["read"],
    });
    const victim = await ak.create({ accountId: "acct_B", scopes: ["write"] });

    const res = await fetch(`${base}/sdk-keys/${victim.id}`, {
      method: "DELETE",
      headers: auth(attacker.key),
    });
    expect(res.status).toBe(404);

    const check = await ak.validate(victim.key);
    expect(check.valid).toBe(true);
  });

  it("lets an account revoke its own key", async () => {
    const owner = await ak.create({ accountId: "acct_self", scopes: ["read"] });
    const own = await ak.create({ accountId: "acct_self", scopes: ["read"] });

    const res = await fetch(`${base}/sdk-keys/${own.id}`, {
      method: "DELETE",
      headers: auth(owner.key),
    });
    expect(res.status).toBe(200);
  });

  // Regression: POST /sdk-keys let a key mint a key with scopes it didn't
  // hold (privilege escalation). Found by /qa on 2026-06-18.
  it("rejects minting a key with scopes the caller lacks", async () => {
    const limited = await ak.create({
      accountId: "acct_lim",
      scopes: ["read"],
    });

    const res = await fetch(`${base}/sdk-keys`, {
      method: "POST",
      headers: auth(limited.key),
      body: JSON.stringify({ scopes: ["admin"] }),
    });
    expect(res.status).toBe(403);
  });

  it("inherits caller scopes instead of going unlimited when scopes omitted", async () => {
    const limited = await ak.create({
      accountId: "acct_inherit",
      scopes: ["read"],
    });

    const res = await fetch(`${base}/sdk-keys`, {
      method: "POST",
      headers: auth(limited.key),
      body: JSON.stringify({}),
    });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.scopes).toEqual(["read"]);
  });

  it("allows minting a key with a subset of caller scopes", async () => {
    const caller = await ak.create({
      accountId: "acct_subset",
      scopes: ["read", "write"],
    });

    const res = await fetch(`${base}/sdk-keys`, {
      method: "POST",
      headers: auth(caller.key),
      body: JSON.stringify({ scopes: ["read"] }),
    });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.scopes).toEqual(["read"]);
  });

  // Regression: unauthenticated POST /signup minted arbitrary scopes (incl.
  // admin) and unlimited keys when signupScopes was not configured. Found by
  // /qa on 2026-06-18.
  it("does not let anonymous /signup mint scopes when signupScopes is unset", async () => {
    const res = await fetch(`${base}/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: "attacker@evil.com",
        scopes: ["admin"],
        budget_cents: null,
        expires_in: "365d",
      }),
    });
    expect(res.status).toBe(400);
  });

  it("issues a scopeless (not unlimited) key when /signup omits scopes", async () => {
    const res = await fetch(`${base}/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "user@example.com" }),
    });
    expect(res.status).toBe(201);
    const body = await res.json();
    expect(body.scopes).toEqual([]);
  });

  it("maps a malformed expires_in to 400, not 500", async () => {
    const res = await fetch(`${base}/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "user@example.com", expires_in: "abc" }),
    });
    expect(res.status).toBe(400);
  });
});

describe("routes (signup with configured scopes)", () => {
  let server: Server;
  let base: string;

  beforeAll(() => {
    const app = express();
    app.use(express.json());
    app.use(createAgentKeyRoutes(ak, { signupScopes: ["read"] }));
    server = app.listen(0);
    const addr = server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    base = `http://localhost:${port}`;
  });

  afterAll(() => {
    server.close();
  });

  it("allows a configured scope and rejects anything else", async () => {
    const ok = await fetch(`${base}/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "user@example.com", scopes: ["read"] }),
    });
    expect(ok.status).toBe(201);

    const bad = await fetch(`${base}/signup`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: "user@example.com", scopes: ["admin"] }),
    });
    expect(bad.status).toBe(400);
  });
});

describe("fixes — 2026-06-18 bug-hunt regressions", () => {
  // #4: an unvalidated budget_period silently stored a bad string and disabled
  // resets (one-shot lifetime cap). create() now rejects it like a bad scope.
  it("create rejects an invalid budget_period", async () => {
    await expect(
      ak.create({
        accountId: "acct_badperiod",
        budgetCents: 100,
        budgetPeriod: "weekly" as unknown as "day",
      }),
    ).rejects.toThrow(/Invalid budget period/);
  });

  // #14: validateScopes hard-allowed 'admin' regardless of the allow-list. It is
  // now gated like any other scope.
  it("create rejects 'admin' when validScopes excludes it", async () => {
    const limitedAk = new AgentKey({
      pool,
      keyPrefix: "test_",
      validScopes: ["read"],
    });
    await expect(
      limitedAk.create({ accountId: "acct_noadmin", scopes: ["admin"] }),
    ).rejects.toThrow(/Invalid scopes/);
  });

  // #10: a positive sub-half-cent cost rounded to a free $0 charge. Rounds up now.
  it("trackUsage charges at least one cent for a sub-cent cost", async () => {
    const k = await ak.create({ accountId: "acct_subcent", budgetCents: 100 });
    const r = await ak.trackUsage(k.key, { costCents: 0.4 });
    expect(r.success).toBe(true);
    expect(r.budgetUsedCents).toBe(1);
  });

  // #11: a $0 charge reported fabricated "0 used / unlimited remaining".
  it("trackUsage no-ops a $0 charge without fabricating budget numbers", async () => {
    const k = await ak.create({ accountId: "acct_zerocharge", budgetCents: 100 });
    await ak.trackUsage(k.key, { costCents: 50 });
    const r = await ak.trackUsage(k.key, { costCents: 0 });
    expect(r.success).toBe(true);
    expect(r.budgetUsedCents).toBeUndefined();
    expect(r.budgetRemainingCents).toBeUndefined();
  });

  // #1: middleware had no try/catch — a rejecting validate() (DB fault) hung the
  // request and could crash the process. It now fails closed with a 500.
  describe("middleware fails closed when validate throws", () => {
    let server: Server;
    let base: string;
    beforeAll(() => {
      const brokenAk = new AgentKey({
        pool: {
          query: () => Promise.reject(new Error("db down")),
        } as unknown as pg.Pool,
      });
      const app = express();
      app.use(express.json());
      app.get("/protected", agentKeyMiddleware(brokenAk), (_req, res) =>
        res.json({ ok: true }),
      );
      server = app.listen(0);
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      base = `http://localhost:${port}`;
    });
    afterAll(() => server.close());

    it("returns 500, not a hang or a crash", async () => {
      const res = await fetch(`${base}/protected`, {
        headers: { Authorization: "Bearer test_anything" },
      });
      expect(res.status).toBe(500);
    });
  });

  // #2 + #3: route-level ownership and delegation attenuation.
  describe("route attenuation", () => {
    let server: Server;
    let base: string;
    beforeAll(() => {
      const app = express();
      app.use(express.json());
      // requireEmailForSignup:false exercises the anonymous-signup path.
      app.use(
        createAgentKeyRoutes(ak, {
          requireEmailForSignup: false,
          signupScopes: ["read"],
        }),
      );
      server = app.listen(0);
      const addr = server.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      base = `http://localhost:${port}`;
    });
    afterAll(() => server.close());

    const auth = (key: string) => ({
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
    });

    // #2: anonymous signups must each get their own account, not a shared bucket,
    // or they could revoke/mint against each other's keys.
    it("gives each anonymous /signup its own account", async () => {
      const a = await (
        await fetch(`${base}/signup`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "{}",
        })
      ).json();
      const b = await (
        await fetch(`${base}/signup`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "{}",
        })
      ).json();

      const res = await fetch(`${base}/sdk-keys/${a.id}`, {
        method: "DELETE",
        headers: auth(b.key),
      });
      expect(res.status).toBe(404);
      const stillValid = await ak.validate(a.key);
      expect(stillValid.valid).toBe(true);
    });

    // #3: a budgeted key cannot mint a larger or uncapped child.
    it("attenuates child budget to the caller", async () => {
      const caller = await ak.create({
        accountId: "acct_atten_budget",
        scopes: ["read"],
        budgetCents: 1000,
        budgetPeriod: "month",
      });
      const over = await fetch(`${base}/sdk-keys`, {
        method: "POST",
        headers: auth(caller.key),
        body: JSON.stringify({ budget_cents: 5000 }),
      });
      expect(over.status).toBe(403);
      const missing = await fetch(`${base}/sdk-keys`, {
        method: "POST",
        headers: auth(caller.key),
        body: JSON.stringify({}),
      });
      expect(missing.status).toBe(403);
      const ok = await fetch(`${base}/sdk-keys`, {
        method: "POST",
        headers: auth(caller.key),
        body: JSON.stringify({ budget_cents: 500 }),
      });
      expect(ok.status).toBe(201);
    });

    // #3: a short-lived key cannot mint a longer-lived child.
    it("attenuates child expiry to the caller", async () => {
      const caller = await ak.create({
        accountId: "acct_atten_expiry",
        scopes: ["read"],
        expiresIn: "1h",
      });
      const longer = await fetch(`${base}/sdk-keys`, {
        method: "POST",
        headers: auth(caller.key),
        body: JSON.stringify({ expires_in: "365d" }),
      });
      expect(longer.status).toBe(403);
      const missing = await fetch(`${base}/sdk-keys`, {
        method: "POST",
        headers: auth(caller.key),
        body: JSON.stringify({}),
      });
      expect(missing.status).toBe(403);
      const ok = await fetch(`${base}/sdk-keys`, {
        method: "POST",
        headers: auth(caller.key),
        body: JSON.stringify({ expires_in: "30m" }),
      });
      expect(ok.status).toBe(201);
    });
  });
});
