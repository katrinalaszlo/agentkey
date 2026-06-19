export function migrationSQL(tableName: string): string[] {
  return [
    `ALTER TABLE ${tableName} ADD COLUMN IF NOT EXISTS user_id TEXT`,
    `ALTER TABLE ${tableName} ADD COLUMN IF NOT EXISTS scopes TEXT[]`,
    `ALTER TABLE ${tableName} ADD COLUMN IF NOT EXISTS budget_cents INTEGER`,
    `ALTER TABLE ${tableName} ADD COLUMN IF NOT EXISTS budget_used_cents INTEGER DEFAULT 0`,
    `ALTER TABLE ${tableName} ADD COLUMN IF NOT EXISTS budget_period TEXT`,
    `ALTER TABLE ${tableName} ADD COLUMN IF NOT EXISTS budget_reset_at TIMESTAMPTZ`,
    `ALTER TABLE ${tableName} ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ`,
    `ALTER TABLE ${tableName} ADD COLUMN IF NOT EXISTS delegated_by TEXT`,
    // external_subject binds a budget row to an external identity (e.g. a Clerk
    // M2M machine id) so validate/trackUsage can key on it instead of the raw
    // key hash. Partial unique index: regular ak_ keys leave it NULL and must
    // not collide, so the constraint applies only to rows that set it.
    `ALTER TABLE ${tableName} ADD COLUMN IF NOT EXISTS external_subject TEXT`,
    `CREATE UNIQUE INDEX IF NOT EXISTS ${tableName}_external_subject_key
       ON ${tableName} (external_subject) WHERE external_subject IS NOT NULL`,
  ];
}
