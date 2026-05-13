# agentkey

TypeScript library. Adds scoped, budgeted, time-bounded API keys to any Express + PostgreSQL app.

## Build & Test

```bash
npm install
npm test
npm run build
```

## Architecture

- `src/index.ts`: AgentKey class (create, validate, trackUsage, revoke, migrate, hasScope)
- `src/middleware.ts`: Express middleware factory
- `src/types.ts`: TypeScript interfaces
- `src/sql.ts`: Migration SQL

## Key design decisions

- Keys are hashed with SHA-256 before storage. Raw key returned once on creation, never again.
- `scopes: null` means unlimited (backwards compatible with existing unscoped keys).
- `budget_cents: null` means no budget cap (unlimited spend).
- Budget tracks cost in cents, not request count. An agent making 10 requests at $50 each hits a $500 budget, not a 10-request rate limit.
- Soft revoke (revoked_at timestamp) not hard delete.
- Express middleware checks scope before handler runs. Budget is tracked explicitly via trackUsage() after the expensive operation completes.

## Conventions

- All money values in integer cents (no floats).
- Key prefix: `ak_` by default, configurable.
- Expiry durations: string format ('1h', '7d', '30d').
- PostgreSQL required. Uses TEXT[] for scopes array.
