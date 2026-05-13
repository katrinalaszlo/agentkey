import crypto from "crypto";
import type { Pool } from "pg";
import { migrationSQL } from "./sql.js";
import type {
  AgentKeyOptions,
  CreateKeyOptions,
  CreateKeyResult,
  ValidateResult,
  ValidateFailure,
  TrackUsageResult,
} from "./types.js";

export type {
  AgentKeyOptions,
  CreateKeyOptions,
  CreateKeyResult,
  ValidateResult,
  ValidateFailure,
  TrackUsageResult,
};

export { agentKeyMiddleware } from "./middleware.js";
export { createAgentKeyRoutes } from "./routes.js";
export type { RouteOptions } from "./routes.js";

function parseDuration(dur: string): number {
  const match = dur.match(/^(\d+)(h|d|m)$/);
  if (!match) throw new Error(`Invalid duration: ${dur}`);
  const n = parseInt(match[1], 10);
  const unit = match[2];
  if (unit === "h") return n * 60 * 60 * 1000;
  if (unit === "d") return n * 24 * 60 * 60 * 1000;
  if (unit === "m") return n * 30 * 24 * 60 * 60 * 1000;
  throw new Error(`Unknown unit: ${unit}`);
}

function nextCalendarMonth(from: Date): Date {
  return new Date(from.getFullYear(), from.getMonth() + 1, from.getDate());
}

function nextDay(from: Date): Date {
  return new Date(from.getTime() + 24 * 60 * 60 * 1000);
}

export class AgentKey {
  private pool: Pool;
  private tableName: string;
  private keyPrefix: string;
  private validScopes: Set<string> | null;

  constructor(opts: AgentKeyOptions) {
    this.pool = opts.pool;
    this.tableName = opts.tableName ?? "sdk_api_keys";
    this.keyPrefix = opts.keyPrefix ?? "ak_";
    this.validScopes = opts.validScopes ? new Set(opts.validScopes) : null;
  }

  async migrate(): Promise<void> {
    for (const sql of migrationSQL(this.tableName)) {
      await this.pool.query(sql);
    }
  }

  validateScopes(scopes: string[]): { valid: boolean; invalid?: string[] } {
    if (!this.validScopes) return { valid: true };
    const invalid = scopes.filter(
      (s) => !this.validScopes!.has(s) && s !== "admin",
    );
    return invalid.length === 0 ? { valid: true } : { valid: false, invalid };
  }

  async create(opts: CreateKeyOptions): Promise<CreateKeyResult> {
    if (opts.scopes && this.validScopes) {
      const check = this.validateScopes(opts.scopes);
      if (!check.valid) {
        throw new Error(`Invalid scopes: ${check.invalid!.join(", ")}`);
      }
    }

    const rawKey = `${this.keyPrefix}${crypto.randomBytes(24).toString("hex")}`;
    const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");
    const keyPrefix = rawKey.slice(0, this.keyPrefix.length + 8);

    const expiresAt = opts.expiresIn
      ? new Date(Date.now() + parseDuration(opts.expiresIn))
      : null;

    const now = new Date();
    const budgetResetAt =
      opts.budgetPeriod === "month"
        ? nextCalendarMonth(now)
        : opts.budgetPeriod === "day"
          ? nextDay(now)
          : null;

    const result = await this.pool.query(
      `INSERT INTO ${this.tableName}
        (account_id, user_id, key_hash, key_prefix, name, scopes, budget_cents, budget_used_cents,
         budget_period, budget_reset_at, expires_at, delegated_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 0, $8, $9, $10, $11)
       RETURNING id`,
      [
        opts.accountId,
        opts.userId ?? null,
        keyHash,
        keyPrefix,
        opts.name ?? "default",
        opts.scopes ?? null,
        opts.budgetCents ?? null,
        opts.budgetPeriod ?? null,
        budgetResetAt,
        expiresAt,
        opts.delegatedBy ?? null,
      ],
    );

    return {
      key: rawKey,
      id: result.rows[0].id,
      scopes: opts.scopes ?? null,
      budgetCents: opts.budgetCents ?? null,
      budgetPeriod: opts.budgetPeriod ?? null,
      expiresAt: expiresAt?.toISOString() ?? null,
    };
  }

  async validate(rawKey: string): Promise<ValidateResult | ValidateFailure> {
    const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");

    const result = await this.pool.query(
      `SELECT id, account_id, user_id, name, scopes, budget_cents, budget_used_cents,
              budget_period, budget_reset_at, expires_at, delegated_by, revoked_at
       FROM ${this.tableName} WHERE key_hash = $1`,
      [keyHash],
    );

    if (result.rows.length === 0) {
      return { valid: false, reason: "invalid" };
    }

    const row = result.rows[0];

    if (row.revoked_at) {
      return { valid: false, reason: "revoked" };
    }

    if (row.expires_at && new Date(row.expires_at) < new Date()) {
      return { valid: false, reason: "expired" };
    }

    if (
      row.budget_cents != null &&
      (row.budget_used_cents ?? 0) >= row.budget_cents
    ) {
      return { valid: false, reason: "budget_exceeded" };
    }

    if (row.budget_reset_at && new Date(row.budget_reset_at) < new Date()) {
      const resetFrom = new Date(row.budget_reset_at);
      const newResetAt =
        row.budget_period === "month"
          ? nextCalendarMonth(resetFrom)
          : nextDay(resetFrom);

      await this.pool.query(
        `UPDATE ${this.tableName} SET budget_used_cents = 0, budget_reset_at = $1 WHERE id = $2`,
        [newResetAt.toISOString(), row.id],
      );
      row.budget_used_cents = 0;
      row.budget_reset_at = newResetAt;
    }

    // Fire-and-forget last_used_at update
    this.pool
      .query(
        `UPDATE ${this.tableName} SET last_used_at = NOW() WHERE id = $1`,
        [row.id],
      )
      .catch(() => {});

    const budgetRemaining =
      row.budget_cents != null
        ? Math.max(0, row.budget_cents - (row.budget_used_cents ?? 0))
        : null;

    return {
      valid: true,
      id: row.id,
      accountId: row.account_id,
      userId: row.user_id ?? null,
      scopes: row.scopes ?? null,
      budgetCents: row.budget_cents ?? null,
      budgetUsedCents: row.budget_used_cents ?? 0,
      budgetRemainingCents: budgetRemaining,
      budgetPeriod: row.budget_period ?? null,
      budgetResetAt: row.budget_reset_at?.toISOString() ?? null,
      expiresAt: row.expires_at?.toISOString() ?? null,
      delegatedBy: row.delegated_by ?? null,
      name: row.name,
    };
  }

  async trackUsage(
    rawKey: string,
    opts: { costCents: number },
  ): Promise<TrackUsageResult> {
    if (opts.costCents <= 0) {
      return { success: true, budgetUsedCents: 0, budgetRemainingCents: null };
    }

    const keyHash = crypto.createHash("sha256").update(rawKey).digest("hex");

    const result = await this.pool.query(
      `SELECT id, budget_cents, budget_used_cents FROM ${this.tableName}
       WHERE key_hash = $1 AND revoked_at IS NULL`,
      [keyHash],
    );

    if (result.rows.length === 0) {
      return { success: false, reason: "invalid_key" };
    }

    const row = result.rows[0];
    const costRounded = Math.round(opts.costCents);
    const newUsed = (row.budget_used_cents ?? 0) + costRounded;

    if (row.budget_cents != null && newUsed > row.budget_cents) {
      return { success: false, reason: "budget_exceeded" };
    }

    await this.pool.query(
      `UPDATE ${this.tableName} SET budget_used_cents = COALESCE(budget_used_cents, 0) + $1 WHERE id = $2`,
      [costRounded, row.id],
    );

    return {
      success: true,
      budgetUsedCents: newUsed,
      budgetRemainingCents:
        row.budget_cents != null
          ? Math.max(0, row.budget_cents - newUsed)
          : null,
    };
  }

  hasScope(result: ValidateResult, scope: string): boolean {
    if (result.scopes === null) return true;
    return result.scopes.includes(scope) || result.scopes.includes("admin");
  }

  async revoke(keyId: number): Promise<void> {
    await this.pool.query(
      `UPDATE ${this.tableName} SET revoked_at = NOW() WHERE id = $1`,
      [keyId],
    );
  }
}
