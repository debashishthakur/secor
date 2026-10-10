export function requireAdmin(req: any, res: any, next: any) { next(); }
export const middlewares = { mustBeAdmin: requireAdmin };
