---
name: agentkey
description: >-
  Scoped, budgeted, time-bounded API keys for AI agents. Use when adding
  per-key scoping, per-key budget caps, key expiry, or delegation to an
  Express + PostgreSQL app. Covers create (scopes, budget, expiry, delegation),
  validate (check scopes, budget remaining, expiry), trackUsage (decrement
  budget in cents not requests), hasScope (with admin override), revoke,
  migrate, and Express middleware. Use when building agent self-serve APIs,
  agent auth, capability-based access control, or any system where different
  API keys on the same account need different permissions and spending limits.
metadata:
  author: Katrina Laszlo
  version: "0.1.0"
---

# agentkey

Scoped, budgeted, time-bounded API keys for AI agents. Fills the four layers between Clerk (identity) and Stripe (billing).

## Install

```
npm install agentkey
```

## Core API

```typescript
const ak = new AgentKey({ pool, validScopes: ['usage.read', 'proxy.chat', 'billing.read'] });

// Create
const key = await ak.create({ accountId, scopes: ['usage.read'], budgetCents: 5000, budgetPeriod: 'month', expiresIn: '7d', delegatedBy: 'user_123' });

// Validate
const result = await ak.validate(key.key);
// { valid: true, scopes, budgetRemainingCents, expiresAt, ... }

// Track spend (cents, not requests)
await ak.trackUsage(key.key, { costCents: 15 });

// Check scope (null scopes = unlimited, 'admin' overrides all)
ak.hasScope(result, 'proxy.chat');

// Revoke
await ak.revoke(key.id);
```

## Express middleware

```typescript
import { agentKeyMiddleware } from 'agentkey';
app.get('/api/usage', agentKeyMiddleware(ak, { scope: 'usage.read' }), handler);
```

Returns 401 (invalid/expired/revoked), 403 (insufficient scope), or 429 (budget exceeded).

## Key design rules

- `scopes: null` = unlimited (backwards compatible with existing unscoped keys)
- `budget_cents: null` = no cap
- Budget tracks cost in cents, not request count
- Calendar month reset (not 30 days flat)
- Fire-and-forget last_used_at (doesn't block validation)
- Admin scope overrides all scope checks
- validScopes option restricts which scopes can be created

## Migration

```typescript
await ak.migrate(); // adds columns to existing keys table
```
