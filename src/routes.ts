import { Router, Request, Response } from "express";
import type { AgentKey } from "./index.js";
import type { ValidateResult } from "./types.js";
import { agentKeyMiddleware } from "./middleware.js";

declare global {
  namespace Express {
    interface Request {
      agentKey?: ValidateResult;
    }
  }
}

export interface RouteOptions {
  signupRateLimit?: number;
  signupScopes?: string[];
  requireEmailForSignup?: boolean;
}

export function createAgentKeyRoutes(
  ak: AgentKey,
  opts?: RouteOptions,
): Router {
  const router = Router();

  // POST /signup - agent gets a scoped key with just an email
  router.post("/signup", async (req: Request, res: Response) => {
    try {
      const { email, scopes, budget_cents, budget_period, expires_in, name } =
        req.body;

      if (opts?.requireEmailForSignup !== false) {
        if (
          !email ||
          typeof email !== "string" ||
          !email.includes("@") ||
          email.length > 255
        ) {
          return res.status(400).json({ error: "Valid email is required" });
        }
      }

      // Fail closed. /signup is unauthenticated, so a caller may only receive
      // scopes the integrator has explicitly allowed via signupScopes. With
      // signupScopes unset, no scopes are grantable — never pass caller scopes
      // (or a null = unlimited scope) straight through, or anyone could mint an
      // admin key. A key with an empty scope set passes no scope gate.
      const allowedScopes = opts?.signupScopes ?? [];
      let grantedScopes: string[];
      if (Array.isArray(scopes)) {
        const disallowed = scopes.filter(
          (s: string) => !allowedScopes.includes(s),
        );
        if (disallowed.length > 0) {
          return res.status(400).json({
            error: `Scopes not allowed on signup: ${disallowed.join(", ")}`,
            allowed: allowedScopes,
          });
        }
        grantedScopes = scopes;
      } else {
        grantedScopes = allowedScopes;
      }

      const key = await ak.create({
        accountId: email ?? "anonymous",
        scopes: grantedScopes,
        budgetCents: budget_cents ?? null,
        budgetPeriod: budget_period ?? null,
        expiresIn: expires_in ?? "24h",
        name: name ?? "default",
      });

      res.status(201).json(key);
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      if (msg.includes("Invalid scopes") || msg.includes("Invalid duration")) {
        return res.status(400).json({ error: msg });
      }
      console.error("POST /signup error:", error);
      res.status(500).json({ error: "Failed to create key" });
    }
  });

  // GET /sdk-keys/me - agent introspects its own key
  router.get(
    "/sdk-keys/me",
    agentKeyMiddleware(ak),
    async (req: Request, res: Response) => {
      if (!req.agentKey) {
        return res.status(401).json({ error: "No valid key" });
      }
      res.json(req.agentKey);
    },
  );

  // POST /sdk-keys - create additional keys (requires existing auth)
  router.post(
    "/sdk-keys",
    agentKeyMiddleware(ak),
    async (req: Request, res: Response) => {
      try {
        if (!req.agentKey) {
          return res.status(401).json({ error: "Authentication required" });
        }

        const { scopes, budget_cents, budget_period, expires_in, name } =
          req.body;

        // A key may only grant scopes it already holds. Otherwise a
        // read-only key could mint an admin (or unlimited) key for its
        // own account.
        const callerScopes = req.agentKey.scopes;
        const callerIsLimited =
          callerScopes !== null && !callerScopes.includes("admin");
        let childScopes: string[] | null = Array.isArray(scopes)
          ? scopes
          : null;
        if (callerIsLimited) {
          if (childScopes === null) {
            // Don't let an unspecified request become an unlimited key —
            // inherit the caller's own scopes instead.
            childScopes = callerScopes;
          } else {
            const disallowed = childScopes.filter(
              (s) => !callerScopes!.includes(s),
            );
            if (disallowed.length > 0) {
              return res.status(403).json({
                error: `Cannot grant scopes you do not have: ${disallowed.join(", ")}`,
              });
            }
          }
        }

        const key = await ak.create({
          accountId: req.agentKey.accountId,
          userId: req.agentKey.userId,
          scopes: childScopes,
          budgetCents: budget_cents ?? null,
          budgetPeriod: budget_period ?? null,
          expiresIn: expires_in ?? null,
          delegatedBy: req.agentKey.userId ?? String(req.agentKey.accountId),
          name: name ?? "default",
        });

        res.status(201).json(key);
      } catch (error) {
        const msg = error instanceof Error ? error.message : String(error);
        if (
          msg.includes("Invalid scopes") ||
          msg.includes("Invalid duration")
        ) {
          return res.status(400).json({ error: msg });
        }
        console.error("POST /sdk-keys error:", error);
        res.status(500).json({ error: "Failed to create key" });
      }
    },
  );

  // DELETE /sdk-keys/:id - revoke a key
  router.delete(
    "/sdk-keys/:id",
    agentKeyMiddleware(ak),
    async (req: Request, res: Response) => {
      try {
        if (!req.agentKey) {
          return res.status(401).json({ error: "Authentication required" });
        }
        const keyId = parseInt(req.params.id, 10);
        if (isNaN(keyId)) {
          return res.status(400).json({ error: "Invalid key ID" });
        }
        // Scope revocation to the caller's account so one key can't revoke
        // another account's keys by guessing sequential IDs.
        const revoked = await ak.revoke(keyId, req.agentKey.accountId);
        if (!revoked) {
          return res.status(404).json({ error: "Key not found" });
        }
        res.json({ revoked: true });
      } catch (error) {
        console.error("DELETE /sdk-keys/:id error:", error);
        res.status(500).json({ error: "Failed to revoke key" });
      }
    },
  );

  return router;
}
