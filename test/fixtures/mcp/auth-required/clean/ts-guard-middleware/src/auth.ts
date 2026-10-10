import type { NextFunction, Request, Response } from "express";

export function authenticate(req: Request, res: Response, next: NextFunction) {
  const session = req.header("x-session-token");
  if (!session) return res.status(401).json({ error: "login required" });
  next();
}
