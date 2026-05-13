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
  ];
}
