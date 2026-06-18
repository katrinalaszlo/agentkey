# agentkey

Scoped, budgeted, time-bounded API keys for AI agents.

## Why

When I led self-serve at a usage-based data company, one of the most common requests was credit limits per API key. Users have asked for the same at Tanso. Account- and user-level limits are critical for enterprises, but they're heavy. What's the simple version for startups?

agentkey is that: scope what a key can do, cap what it can spend, set when it expires, and record which human authorized it. It adds a few columns to your existing keys table — it doesn't replace your auth.

## What it covers

The layers nobody else covers, per key:

| Layer | What it controls | Who covers it today |
|---|---|---|
| Identity | Who is this | Clerk, Auth0 |
| Account billing | How much can this org spend | Stripe, Metronome |
| **Key scoping** | **What can this key do** | **agentkey** |
| **Key budgeting** | **How much can this key spend** | **agentkey** |
| **Key expiry** | **When does access end** | **agentkey** |
| **Delegation** | **On whose behalf** | **agentkey** |

## Install

```bash
npm install @katrinalaszlo/agentkey
```

## Quick Start

```typescript
import { AgentKey } from '@katrinalaszlo/agentkey';

const ak = new AgentKey({ pool }); // pass your pg Pool

// Create a scoped key with a budget
const key = await ak.create({
  accountId: 'acct_123',
  scopes: ['usage.read', 'proxy.chat'],
  budgetCents: 5000,        // $50 cap
  budgetPeriod: 'month',
  expiresIn: '7d',
  delegatedBy: 'user_456',  // human who authorized this agent
  name: 'sales-agent',
});
// => { key: 'ak_7f3a...', id: 42, expiresAt: '2026-05-20T...' }

// Validate on every request
const result = await ak.validate(key.key);
// => { valid: true, scopes: ['usage.read', 'proxy.chat'],
//      budgetCents: 5000, budgetUsedCents: 1200,
//      budgetRemainingCents: 3800, expiresAt: '...',
//      delegatedBy: 'user_456', accountId: 'acct_123' }

// Track spend after an LLM call
await ak.trackUsage(key.key, { costCents: 15 });

// Check if a scope is allowed
ak.hasScope(result, 'proxy.chat');  // true
ak.hasScope(result, 'billing.write'); // false
```

## How It Works

agentkey adds columns to your existing API keys table and provides middleware to enforce scopes and budgets on every request.

**One account, multiple keys, different capabilities:**

```
Account: Acme Corp (Pro plan, $100/month)
  |
  |-- ak_sales_...    scopes: [proxy.chat]         budget: $40/mo
  |-- ak_analytics_.. scopes: [usage.read]          budget: $0 (free endpoints only)
  |-- ak_agent_...    scopes: [proxy.chat, usage.read]  budget: $30/mo  expires: 7d
```

The account's plan sets the ceiling. Keys subdivide it. No single key can blow the whole month's budget.

## API

### `new AgentKey(options)`

```typescript
const ak = new AgentKey({
  pool,              // pg Pool instance
  tableName: 'sdk_api_keys',  // default
  keyPrefix: 'ak_',           // default
});
```

### `ak.create(options)`

Create a new scoped key.

| Option | Type | Required | Description |
|---|---|---|---|
| `accountId` | string/number | yes | Account this key belongs to |
| `scopes` | string[] | no | Allowed actions. null = unlimited |
| `budgetCents` | number | no | Spending cap in cents. null = unlimited |
| `budgetPeriod` | 'day' \| 'month' \| null | no | Budget reset interval |
| `expiresIn` | string | no | Duration: `m`=minutes, `h`=hours, `d`=days, `mo`=months (e.g. `'30m'`, `'1h'`, `'7d'`, `'1mo'`). null = no expiry |
| `delegatedBy` | string | no | User ID of the human who authorized this key |
| `name` | string | no | Label for this key |

### `ak.validate(rawKey)`

Validate a key and return its metadata. Returns `{ valid: false, reason: string }` for invalid, expired, or revoked keys.

### `ak.trackUsage(rawKey, { costCents })`

Increment budget usage. Returns `{ success: false, reason: 'budget_exceeded' }` if the key's budget cap would be exceeded.

### `ak.hasScope(validationResult, scope)`

Check if a validated key has a specific scope. Returns boolean.

### `ak.revoke(keyId, accountId?)`

Soft-revoke a key (sets revoked_at timestamp). Returns `true` if a key was revoked, `false` if nothing matched. Pass `accountId` to only revoke a key that account owns — the built-in `DELETE /sdk-keys/:id` route does this so one key can't revoke another account's keys by guessing IDs.

## Express Middleware

```typescript
import { agentKeyMiddleware } from '@katrinalaszlo/agentkey';

// Protect routes with scope checks
app.get('/api/usage', agentKeyMiddleware(ak, { scope: 'usage.read' }), handler);
app.post('/api/proxy', agentKeyMiddleware(ak, { scope: 'proxy.chat' }), handler);

// Budget is tracked automatically when you call ak.trackUsage()
```

## Self-Serve Routes (optional)

`createAgentKeyRoutes(ak, opts)` mounts `POST /signup`, `GET /sdk-keys/me`, `POST /sdk-keys`, and `DELETE /sdk-keys/:id`.

```typescript
import { createAgentKeyRoutes } from '@katrinalaszlo/agentkey';

app.use(createAgentKeyRoutes(ak, { signupScopes: ['proxy.chat'] }));
```

Security model:
- `POST /signup` is **unauthenticated** (an agent self-serves a key with just an email). It only grants scopes listed in `signupScopes`. With `signupScopes` unset it issues a **scopeless** key — it never passes caller-supplied scopes (or an unlimited scope) through, so no one can mint an `admin` key from this endpoint. Set your own `budget_cents`/`expires_in` caps in front of it if you expose it publicly.
- `POST /sdk-keys` requires a valid key and can only grant scopes the calling key already holds.
- `DELETE /sdk-keys/:id` only revokes keys owned by the calling key's account.

## Database Migration

agentkey adds columns to your existing keys table:

```sql
ALTER TABLE sdk_api_keys
  ADD COLUMN IF NOT EXISTS user_id TEXT,
  ADD COLUMN IF NOT EXISTS scopes TEXT[],
  ADD COLUMN IF NOT EXISTS budget_cents INTEGER,
  ADD COLUMN IF NOT EXISTS budget_used_cents INTEGER DEFAULT 0,
  ADD COLUMN IF NOT EXISTS budget_period TEXT,
  ADD COLUMN IF NOT EXISTS budget_reset_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS delegated_by TEXT;
```

Run `ak.migrate()` to apply automatically, or use the SQL above in your own migration system.

## Why Not Just Use...

**Clerk/Auth0**: They scope identity, not budget. M2M tokens have scopes but no credit caps, no usage metering per key.

**Stripe/Metronome**: They scope account billing, not per-key. Can't tell which of 15 keys drove the cost.

**Rate limiters**: They scope throughput (requests/min), not dollars. 10 requests at $50 each stays under the rate limit while spending $500.

**Custom code**: This is what everyone builds. It takes weeks, it's different at every company, it has bugs.

## License

MIT
