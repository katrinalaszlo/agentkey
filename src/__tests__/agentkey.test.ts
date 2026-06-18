import { describe, it, expect, beforeAll, afterAll } from "vitest";
import pg from "pg";
import { AgentKey } from "../index.js";

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
    await pool.query(
      "UPDATE sdk_api_keys SET budget_reset_at = NOW() - INTERVAL '5 days' WHERE id = $1",
      [created.id],
    );

    const result = await ak.validate(created.key);
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    expect(result.budgetUsedCents).toBe(0);
    expect(result.budgetRemainingCents).toBe(100);
    // New reset date must be in the future, not the stale past date.
    expect(new Date(result.budgetResetAt!).getTime()).toBeGreaterThan(Date.now());
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

  it("allows unlimited usage with null budget", async () => {
    const created = await ak.create({ accountId: "acct_test_unlimited" });

    const r = await ak.trackUsage(created.key, { costCents: 99999 });
    expect(r.success).toBe(true);
    expect(r.budgetRemainingCents).toBeNull();
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
