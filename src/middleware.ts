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
  };
}
