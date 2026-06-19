import type { Pool } from "pg";

export interface AgentKeyOptions {
  pool: Pool;
  tableName?: string;
  keyPrefix?: string;
  validScopes?: string[];
}

export interface CreateKeyOptions {
  accountId: string | number;
  userId?: string | null;
  scopes?: string[] | null;
  budgetCents?: number | null;
  budgetPeriod?: "day" | "month" | null;
  expiresIn?: string | null;
  delegatedBy?: string | null;
  name?: string;
}

// Options for a budget row bound to an external identity (e.g. a Clerk M2M
// machine id). Same knobs as CreateKeyOptions, but accountId is optional
// (defaults to the subject) because the external identity is the anchor and no
// ak_ key is minted.
export interface EnsureSubjectOptions {
  accountId?: string | number;
  userId?: string | null;
  scopes?: string[] | null;
  budgetCents?: number | null;
  budgetPeriod?: "day" | "month" | null;
  expiresIn?: string | null;
  delegatedBy?: string | null;
  name?: string;
}

export interface CreateKeyResult {
  key: string;
  id: number;
  scopes: string[] | null;
  budgetCents: number | null;
  budgetPeriod: string | null;
  expiresAt: string | null;
}

export interface ValidateResult {
  valid: true;
  id: number;
  accountId: string | number;
  userId: string | null;
  scopes: string[] | null;
  budgetCents: number | null;
  budgetUsedCents: number;
  budgetRemainingCents: number | null;
  budgetPeriod: string | null;
  budgetResetAt: string | null;
  expiresAt: string | null;
  delegatedBy: string | null;
  name: string;
}

export interface ValidateFailure {
  valid: false;
  reason: "invalid" | "expired" | "revoked" | "budget_exceeded";
}

export interface TrackUsageResult {
  success: boolean;
  reason?: "budget_exceeded" | "invalid_key" | "invalid_cost";
  budgetUsedCents?: number;
  budgetRemainingCents?: number | null;
}
