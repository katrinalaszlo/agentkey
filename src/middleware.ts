import type { Request, Response, NextFunction } from "express";
import type { AgentKey } from "./index.js";
import type { ValidateResult } from "./types.js";

declare global {
  namespace Express {
    interface Request {
      agentKey?: ValidateResult;
    }
  }
}

export function agentKeyMiddleware(ak: AgentKey, opts?: { scope?: string }) {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader?.startsWith("Bearer ")) {
        return res.status(401).json({ error: "Missing API key" });
      }

      const rawKey = authHeader.slice(7);
      const result = await ak.validate(rawKey);

      if (!result.valid) {
        const status = result.reason === "budget_exceeded" ? 429 : 401;
        return res.status(status).json({ error: result.reason });
      }

      if (opts?.scope && !ak.hasScope(result, opts.scope)) {
        return res.status(403).json({
          error: "insufficient_scope",
          required: opts.scope,
          available: result.scopes,
        });
      }

      req.agentKey = result;
      next();
    } catch (err) {
      // validate() runs DB queries that reject on routine faults (pool
      // exhaustion, connection reset, statement timeout). Express 4 does not
      // forward a rejected promise from async middleware, so without this the
      // request hangs and the unhandled rejection can crash the process.
      // Fail closed with a 500.
      console.error("agentKeyMiddleware error:", err);
      return res.status(500).json({ error: "auth_unavailable" });
    }
  };
}
