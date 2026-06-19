import { describe, it, expect, beforeAll, afterAll } from "vitest";
import pg from "pg";
import { AgentKey } from "../index.js";

// External-subject enforcement path (used by the Clerk M2M overlay). A budget
// row is anchored to an external identity via ensureSubject, then validated and
// charged by subject instead of by raw ak_ key. Mirrors the by-key coverage in
// agentkey.test.ts: budget cap, period reset, expiry, scope, concurrency.

const TEST_DB =
  process.env.DATABASE_URL ??
  "postgres://postgres:postgres@localhost:5432/postgres";

let pool: pg.Pool;
let ak: AgentKey;

// Own table so this file doesn't race agentkey.test.ts on a shared
// `CREATE TABLE IF NOT EXISTS` (vitest runs test files in parallel, and
// concurrent identical CREATEs collide on the pg_class catalog index).
const TABLE = "sdk_keys_subject_test";

beforeAll(async () => {
  pool = new pg.Pool({ connectionString: TEST_DB });

  await pool.query(`
    CREATE TABLE IF NOT EXISTS ${TABLE} (
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
    tableName: TABLE,
    keyPrefix: "test_",
    validScopes: ["read", "write", "admin"],
  });

  await ak.migrate();
});

afterAll(async () => {
  await pool.query(`DROP TABLE IF EXISTS ${TABLE}`);
  await pool.end();
});

describe("ensureSubject", () => {
  it("creates a subject-bound row that validates with its scopes and budget", async () => {
    await ak.ensureSubject("mach_basic", {
      scopes: ["read"],
      budgetCents: 1000,
      budgetPeriod: "month",
    });

    const result = await ak.validateBySubject("mach_basic");
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    expect(result.scopes).toEqual(["read"]);
    expect(result.budgetCents).toBe(1000);
    expect(result.budgetUsedCents).toBe(0);
    expect(result.budgetRemainingCents).toBe(1000);
  });

  it("is idempotent — a second call does not reset accrued usage", async () => {
    await ak.ensureSubject("mach_idem", { budgetCents: 100 });
    await ak.trackUsageBySubject("mach_idem", { costCents: 40 });

    // Second ensure with different opts must NOT overwrite or reset the row.
    await ak.ensureSubject("mach_idem", { budgetCents: 9999 });

    const result = await ak.validateBySubject("mach_idem");
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    expect(result.budgetCents).toBe(100);
    expect(result.budgetUsedCents).toBe(40);
  });

  it("rejects invalid scopes", async () => {
    await expect(
      ak.ensureSubject("mach_badscope", { scopes: ["nope"] }),
    ).rejects.toThrow("Invalid scopes: nope");
  });

  it("rejects an invalid budget period", async () => {
    await expect(
      ak.ensureSubject("mach_badperiod", {
        budgetCents: 100,
        budgetPeriod: "weekly" as unknown as "day",
      }),
    ).rejects.toThrow(/Invalid budget period/);
  });
});

describe("validateBySubject", () => {
  it("rejects an unknown subject", async () => {
    const result = await ak.validateBySubject("mach_does_not_exist");
    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.reason).toBe("invalid");
  });

  it("rejects an expired subject row", async () => {
    await ak.ensureSubject("mach_expired", { expiresIn: "1d" });
    await pool.query(
      `UPDATE ${TABLE} SET expires_at = NOW() - INTERVAL '1 hour' WHERE external_subject = $1`,
      ["mach_expired"],
    );
    const result = await ak.validateBySubject("mach_expired");
    expect(result.valid).toBe(false);
    if (result.valid) return;
    expect(result.reason).toBe("expired");
  });

  it("resets an exhausted budget once the period rolls over", async () => {
    await ak.ensureSubject("mach_reset", {
      budgetCents: 100,
      budgetPeriod: "day",
    });
    await ak.trackUsageBySubject("mach_reset", { costCents: 100 });

    const blocked = await ak.validateBySubject("mach_reset");
    expect(blocked.valid).toBe(false);
    if (blocked.valid) return;
    expect(blocked.reason).toBe("budget_exceeded");

    await pool.query(
      `UPDATE ${TABLE} SET budget_reset_at = NOW() - INTERVAL '5 days' WHERE external_subject = $1`,
      ["mach_reset"],
    );

    const result = await ak.validateBySubject("mach_reset");
    expect(result.valid).toBe(true);
    if (!result.valid) return;
    expect(result.budgetUsedCents).toBe(0);
    expect(result.budgetRemainingCents).toBe(100);
  });

  it("exposes scopes for hasScope checks", async () => {
    await ak.ensureSubject("mach_scope", { scopes: ["read", "write"] });
    const result = await ak.validateBySubject("mach_scope");
    if (!result.valid) throw new Error("should be valid");
    expect(ak.hasScope(result, "read")).toBe(true);
    expect(ak.hasScope(result, "admin")).toBe(false);
  });
});

describe("trackUsageBySubject", () => {
  it("tracks usage and rejects once the budget is exceeded", async () => {
    await ak.ensureSubject("mach_usage", { budgetCents: 50 });

    const ok = await ak.trackUsageBySubject("mach_usage", { costCents: 40 });
    expect(ok.success).toBe(true);
    expect(ok.budgetRemainingCents).toBe(10);

    const over = await ak.trackUsageBySubject("mach_usage", { costCents: 20 });
    expect(over.success).toBe(false);
    expect(over.reason).toBe("budget_exceeded");
  });

  it("reports invalid_key for an unknown subject", async () => {
    const r = await ak.trackUsageBySubject("mach_ghost", { costCents: 5 });
    expect(r.success).toBe(false);
    expect(r.reason).toBe("invalid_key");
  });

  it("never overspends the budget under concurrent charges", async () => {
    await ak.ensureSubject("mach_race", { budgetCents: 100 });

    const results = await Promise.all(
      Array.from({ length: 20 }, () =>
        ak.trackUsageBySubject("mach_race", { costCents: 20 }),
      ),
    );
    const succeeded = results.filter((r) => r.success).length;
    expect(succeeded).toBe(5); // exactly 100 / 20, never more

    const row = await pool.query(
      `SELECT budget_used_cents FROM ${TABLE} WHERE external_subject = $1`,
      ["mach_race"],
    );
    expect(row.rows[0].budget_used_cents).toBe(100);
  });
});
