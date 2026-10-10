import type { NextFunction, Request, Response } from "express";

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  if (!req.headers.authorization) return res.sendStatus(401);
  next();
}
