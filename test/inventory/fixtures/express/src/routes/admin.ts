const express = require("express");
export function createAdminRouter() {
  const router = express.Router();
  router.use(ensureAdminSession);
  router.delete("/users/:userId", (req, res) => res.end());
  return router;
}
function ensureAdminSession(req, res, next) { next(); }
